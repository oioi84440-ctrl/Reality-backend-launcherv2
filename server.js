/**
 * Reality Client Backend
 * --------------------
 * Serve manifesto remoto (config, Discord, update, criadores, códigos).
 * Qualquer mudança aqui é puxada pelos launchers no próximo start / refresh.
 *
 * Deploy: Render / Railway / VPS / qualquer host Node.
 * Env:
 *   PORT=3000
 *   ADMIN_TOKEN=troque-isso   (obrigatório pra POST /api/admin/*; use um segredo forte)
 *   CORS_ORIGINS=https://painel.exemplo.com (opcional, separado por vírgula)
 *   DEVICE_HMAC_SECRET=...        (verifica X-Reality-Device-Sig; sem ele = so registra)
 *   HWID_ACCT_ANOMALY_MIN=5       (contas distintas em 24h no mesmo HWID => anomalia+webhook)
 *   HWID_AUTOBAN_MIN_ACCOUNTS=0   (0 = DESLIGADO; N = auto-ban do HWID ao passar N contas)
 *   HWID_IP_ANOMALY_MIN=25        (HWIDs distintos por IP/dia => anomalia + webhook)
 */

const fs = require('fs');
const path = require('path');
const express = require('express');
const presence = require('./presence');
const hostguard = require('./hostguard');
const cors = require('cors');
const crypto = require('crypto');

const PORT = process.env.PORT || 3000;
const ADMIN_TOKEN = process.env.ADMIN_TOKEN || 'troque-este-token';
const CORS_ORIGINS = new Set(
  String(process.env.CORS_ORIGINS || '')
    .split(',')
    .map((origin) => origin.trim())
    .filter(Boolean)
);
const DATA_DIR = path.join(__dirname, 'data');
const MANIFEST_FILE = path.join(DATA_DIR, 'manifest.json');
const redeemAttempts = new Map();
let redeemQueue = Promise.resolve();

const app = express();
app.disable('x-powered-by'); // nao anunciar a stack (fingerprint)
// Detras do nginx: confia no X-Forwarded-For SOMENTE vindo do loopback (clientIp).
app.set('trust proxy', 'loopback');

// Rate limit simples em memória (anti flood / raid básico)
const rateLimitMap = new Map();
function rateLimit(ip, key, max, windowMs) {
  const id = String(ip || 'unknown') + '|' + key;
  const now = Date.now();
  let bucket = rateLimitMap.get(id);
  if (!bucket || now > bucket.reset) {
    bucket = { count: 0, reset: now + windowMs };
    rateLimitMap.set(id, bucket);
  }
  bucket.count += 1;
  if (bucket.count > max) return false;
  return true;
}
// limpa map periodicamente
setInterval(() => {
  const now = Date.now();
  for (const [k, v] of rateLimitMap) {
    if (now > v.reset) rateLimitMap.delete(k);
  }
}, 60000);


app.use(cors({
  origin(origin, callback) {
    // Requisições sem Origin (launcher, curl e health checks) continuam aceitas.
    if (!origin || CORS_ORIGINS.has(origin)) {
      return callback(null, true);
    }
    return callback(new Error('origin_not_allowed'));
  }
}));
app.use(express.json({ limit: '2mb' }));

app.use((req, res, next) => {
  res.setHeader('X-Content-Type-Options', 'nosniff');
  res.setHeader('X-Frame-Options', 'DENY');
  // SEGURANCA: o cliente nao escolhe a propria chave do rate limit.
  const ip = clientKey(req);
  if (!rateLimit(ip, 'global', 120, 60000)) {
    return res.status(429).json({ ok: false, error: 'Too many requests' });
  }
  next();
});


/**
 * F01/F16/H1 — IP REAL do cliente, a prova de forja.
 *
 * O nginx (que roda no loopback) SOBRESCREVE o X-Forwarded-For com $remote_addr
 * (nao anexa). O backend so confia nesse header quando a conexao TCP vem de um
 * endereco LOCAL (loopback) — ou seja, do proxy. Acesso direto na porta 3000
 * (compat durante a transicao) usa o proprio socket: mandar X-Forwarded-For na
 * mao nao muda o bucket do rate limit.
 */
function isLocalProxyAddr(addr) {
  const a = String(addr || '');
  return a === '127.0.0.1' || a === '::1' || a === '::ffff:127.0.0.1' || a === 'localhost';
}

function clientIp(req) {
  const sock = String((req.socket && req.socket.remoteAddress) || '').toLowerCase();
  if (isLocalProxyAddr(sock)) {
    const xff = String(req.headers['x-forwarded-for'] || '').split(',')[0].trim();
    if (xff) return xff.slice(0, 64);
    const real = String(req.headers['x-real-ip'] || '').trim();
    if (real) return real.slice(0, 64);
  }
  return sock || 'unknown';
}

function clientKey(req) {
  return clientIp(req).slice(0, 80);
}

function isRateLimited(req) {
  const key = clientKey(req);
  const now = Date.now();
  const recent = (redeemAttempts.get(key) || []).filter((time) => now - time < 60_000);
  recent.push(now);
  redeemAttempts.set(key, recent);
  return recent.length > 20;
}

// ---------- F16: rate limit do resgate em CAMADAS + registro de abuso ----------
// Antes: o POST /api/redeem usava o X-Forwarded-For CRU como chave do limiter
// (forjavel => bucket novo por request) e so existia limite por chave, entao
// trocar IP/uuid multiplicava o orcamento de forca bruta de codigo. Agora:
//   (1) chave = IP REAL (clientKey, a prova de forja por causa do proxy);
//   (2) chave = CONTA (token social ou uuid), para o mesmo dono nao trocar de IP;
//   (3) contador GLOBAL (nao-chaveado) como teto absoluto do endpoint;
//   (4) abuso vai para log + data/redeem-abuse.json (o dono enxerga a tentativa).
// M5: redeemAttempts (Map que crescia para sempre com chaves forjadas) agora tem
// varredura periodica E teto de chaves.
const REDEEM_ATTEMPTS_MAX_KEYS = 50_000;
const REDEEM_ACCT_MAX_PER_MIN = Math.max(5, Math.floor(Number(process.env.REDEEM_ACCT_MAX_PER_MIN) || 10));
const REDEEM_GLOBAL_MAX_PER_MIN = Math.max(10, Math.floor(Number(process.env.REDEEM_GLOBAL_MAX_PER_MIN) || 120));
const REDEEM_ABUSE_FILE = path.join(DATA_DIR, 'redeem-abuse.json');
const REDEEM_ABUSE_MAX = 500;
let redeemGlobal = { start: 0, count: 0 };
let redeemAbuseQueue = Promise.resolve();

setInterval(() => {
  const agora = Date.now();
  for (const [k, lista] of redeemAttempts) {
    const vivos = (Array.isArray(lista) ? lista : []).filter((t) => agora - t < 60_000);
    if (!vivos.length) redeemAttempts.delete(k);
    else redeemAttempts.set(k, vivos);
  }
  if (redeemAttempts.size > REDEEM_ATTEMPTS_MAX_KEYS) {
    const sobra = redeemAttempts.size - REDEEM_ATTEMPTS_MAX_KEYS;
    let i = 0;
    for (const k of redeemAttempts.keys()) { if (i++ >= sobra) break; redeemAttempts.delete(k); }
  }
}, 60_000).unref();

function redeemGlobalAllow() {
  const agora = Date.now();
  if (agora - redeemGlobal.start > 60_000) redeemGlobal = { start: agora, count: 0 };
  redeemGlobal.count += 1;
  return redeemGlobal.count <= REDEEM_GLOBAL_MAX_PER_MIN;
}

/** Registra tentativa abusiva de resgate: log imediato + arquivo (capado). */
function redeemAbuseNote(ip, username, motivo) {
  const registro = {
    at: Date.now(),
    ip: String(ip || '').slice(0, 64),
    username: String(username || '').slice(0, 40),
    motivo: String(motivo || '').slice(0, 40)
  };
  try { console.warn('[redeem] abuso ' + registro.motivo + ' ip=' + registro.ip + ' nick=' + registro.username); } catch (_) {}
  redeemAbuseQueue = redeemAbuseQueue.catch(() => {}).then(() => {
    try {
      let lista = [];
      try {
        if (fs.existsSync(REDEEM_ABUSE_FILE)) {
          const b = JSON.parse(fs.readFileSync(REDEEM_ABUSE_FILE, 'utf-8'));
          if (Array.isArray(b)) lista = b;
        }
      } catch (_) { lista = []; }
      lista.unshift(registro);
      if (lista.length > REDEEM_ABUSE_MAX) lista.length = REDEEM_ABUSE_MAX;
      const tmp = REDEEM_ABUSE_FILE + '.tmp';
      fs.writeFileSync(tmp, JSON.stringify(lista, null, 2), 'utf-8');
      fs.renameSync(tmp, REDEEM_ABUSE_FILE);
    } catch (_) {}
  });
}

function hashRedeemer(username) {
  return require('crypto').createHash('sha256')
    .update(String(username).trim().toLowerCase())
    .digest('hex');
}

function withRedeemLock(task) {
  const result = redeemQueue.then(task, task);
  redeemQueue = result.catch(() => {});
  return result;
}

function ensureData() {
  if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
  if (!fs.existsSync(MANIFEST_FILE)) {
    fs.writeFileSync(
      MANIFEST_FILE,
      JSON.stringify(
        {
          version: 1,
          updatedAt: new Date().toISOString(),
          launcher: {
            latestVersion: '1.0.0',
            downloadUrl: '',
            notes: '',
            sha256: '',
            size: 0,
            platforms: {}
          },
          terms: {
            version: '1.0.0',
            title: 'Termos de Uso e Licença do Reality Client',
            effectiveAt: '2026-08-18'
          },
          discord: {
            reality: 'https://discord.gg/JJHScuCf8y',
            kowa: 'https://discord.gg/6jRn5jKCnd'
          },
          features: { autoCapeMod: true, hideCoreMods: true, offlineSkins: true },
          announcement: { enabled: false, title: '', message: '', url: '' },
          creators: [],
          codes: {}
        },
        null,
        2
      )
    );
  }
}

function readManifest() {
  ensureData();
  return JSON.parse(fs.readFileSync(MANIFEST_FILE, 'utf-8'));
}

function writeManifest(data) {
  ensureData();
  data.updatedAt = new Date().toISOString();
  data.version = (Number(data.version) || 0) + 1;
  persistManifest(data);
  return data;
}

function persistManifest(data) {
  ensureData();
  const tempFile = `${MANIFEST_FILE}.tmp`;
  fs.writeFileSync(tempFile, JSON.stringify(data, null, 2), 'utf-8');
  fs.renameSync(tempFile, MANIFEST_FILE);
  // F02: (re)assina o feed de update a cada publicacao (manifest.sig ao lado).
  try { signUpdateFeed(); } catch (e) { console.error('[manifest] falha ao assinar: ' + ((e && e.message) || e)); }
}

// ---------- F02: ASSINATURA DETACHED do feed de update (Ed25519) ----------
// Problema: o launcher confiava em version/url/sha256 vindos do MESMO feed HTTP —
// o sha256 nao autenticava nada (chegava na mesma mensagem). Agora o servidor
// assina o payload canonico com Ed25519 e o launcher verifica contra a chave
// publica EMBUTIDA no app.
//
// Payload canonico (UTF-8), exatamente nesta ordem e com estes separadores:
//     "<version>|<url>|<sha256>|<size>"
//   - version = manifest.launcher.latestVersion
//   - url     = manifest.launcher.downloadUrl
//   - sha256  = manifest.launcher.sha256 (hex minusculo)
//   - size    = manifest.launcher.size (inteiro, sem separador de milhar)
// Algoritmo: Ed25519 puro (Node: crypto.sign(null, Buffer.from(payload), priv)).
// Chave privada: FORA do repo, em /root/manifest-signing-key.pem (chmod 600),
//   ou no caminho de MANIFEST_KEY_PATH. Nunca versionada, nunca servida.
// Chave publica: servida em GET /api/pubkey (e data/manifest.pub) como
//   { algorithm: 'ed25519', publicKey: '<32 bytes RAW em base64>', keyId }
//   — e ESSE base64 (32 bytes) que o launcher embute.
// Assinatura: base64 (64 bytes) em
//   - campo "sig" do GET /api/update
//   - header "x-reality-manifest-sig" na resposta do GET /api/update
//   - arquivo data/manifest.sig (detached, ao lado do manifest.json) servido em
//     GET /api/manifest.sig
const MANIFEST_SIG_FILE = path.join(DATA_DIR, 'manifest.sig');
const MANIFEST_PUB_FILE = path.join(DATA_DIR, 'manifest.pub');
const MANIFEST_KEY_FILE = String(process.env.MANIFEST_KEY_PATH || '/root/manifest-signing-key.pem');
const MANIFEST_ALG = 'ed25519';
const MANIFEST_SIG_HEADER = 'x-reality-manifest-sig';
let manifestSigCache = { sig: '', keyId: '', payload: '' };
let manifestKeys = null;

function manifestKeyId(publicB64) {
  return crypto.createHash('sha256').update(String(publicB64)).digest('hex').slice(0, 16);
}

function loadManifestKeys() {
  if (manifestKeys) return manifestKeys;
  let priv = null;
  try {
    if (fs.existsSync(MANIFEST_KEY_FILE)) priv = crypto.createPrivateKey(fs.readFileSync(MANIFEST_KEY_FILE, 'utf-8'));
  } catch (e) {
    console.error('[manifest] chave privada ilegivel em ' + MANIFEST_KEY_FILE + ': ' + ((e && e.message) || e));
    priv = null;
  }
  if (!priv) {
    try {
      const par = crypto.generateKeyPairSync('ed25519');
      priv = par.privateKey;
      fs.writeFileSync(MANIFEST_KEY_FILE, priv.export({ type: 'pkcs8', format: 'pem' }), { mode: 0o600 });
      try { fs.chmodSync(MANIFEST_KEY_FILE, 0o600); } catch (_) {}
      console.log('[manifest] par Ed25519 gerado em ' + MANIFEST_KEY_FILE + ' (fora do repo, chmod 600)');
    } catch (e) {
      console.error('[manifest] NAO foi possivel criar a chave de assinatura: ' + ((e && e.message) || e));
      return null;
    }
  }
  try {
    const pub = crypto.createPublicKey(priv);
    const publicPem = pub.export({ type: 'spki', format: 'pem' });
    const der = pub.export({ type: 'spki', format: 'der' });
    const publicB64 = Buffer.from(der.subarray(der.length - 32)).toString('base64'); // 32 bytes RAW
    const keyId = manifestKeyId(publicB64);
    manifestKeys = { privateKey: priv, publicPem, publicB64, keyId };
    try {
      fs.writeFileSync(MANIFEST_PUB_FILE, JSON.stringify({
        algorithm: MANIFEST_ALG,
        publicKey: publicB64,
        keyId,
        payloadFormat: '<version>|<url>|<sha256>|<size>',
        createdAt: new Date().toISOString()
      }, null, 2), 'utf-8');
    } catch (_) {}
    console.log('[manifest] assinatura ATIVA alg=' + MANIFEST_ALG + ' keyId=' + keyId + ' pub=' + publicB64);
    return manifestKeys;
  } catch (e) {
    console.error('[manifest] NAO foi possivel exportar a chave publica: ' + ((e && e.message) || e));
    return null;
  }
}

/** Payload canonico do feed de update — precisa bater EXATAMENTE com o launcher. */
function updateFeedPayload(m) {
  const l = (m && m.launcher) || {};
  return [
    String(l.latestVersion || '1.0.0'),
    String(l.downloadUrl || ''),
    String(l.sha256 || ''),
    String(Number(l.size || 0) || 0)
  ].join('|');
}

function signUpdateFeed() {
  const chaves = loadManifestKeys();
  if (!chaves) return null;
  let payload = '';
  try { payload = updateFeedPayload(readManifest()); } catch (_) { return null; }
  let sig = '';
  try {
    sig = crypto.sign(null, Buffer.from(payload, 'utf-8'), chaves.privateKey).toString('base64');
  } catch (e) {
    console.error('[manifest] falha ao assinar: ' + ((e && e.message) || e));
    return null;
  }
  manifestSigCache = { sig, keyId: chaves.keyId, payload };
  try {
    const tmp = MANIFEST_SIG_FILE + '.tmp';
    fs.writeFileSync(tmp, sig, 'utf-8');
    fs.renameSync(tmp, MANIFEST_SIG_FILE);
  } catch (_) {}
  return manifestSigCache;
}

function manifestSignature() {
  if (manifestSigCache.sig) return manifestSigCache;
  return signUpdateFeed();
}

function requireAdmin(req, res, next) {
  if (ADMIN_TOKEN === 'troque-este-token' || ADMIN_TOKEN.length < 24) {
    // Token padrão nunca deve ser aceito: ele está escrito no próprio código-fonte,
    // então qualquer pessoa com acesso ao repo consegue usar as rotas admin.
    return res.status(503).json({
      error: 'admin_disabled_default_token',
      message: 'Defina a variável de ambiente ADMIN_TOKEN no servidor para liberar as rotas /api/admin/*.'
    });
  }
  const authorization = String(req.headers.authorization || '');
  const bearer = authorization.match(/^Bearer\s+(.+)$/i);
  const token = req.headers['x-admin-token'] || (bearer && bearer[1]);
  if (!token || token !== ADMIN_TOKEN) {
    return res.status(401).json({ error: 'unauthorized' });
  }
  next();
}

// ---------- Lista negra (bans) — genérica, editável sem deploy ----------
// Fonte: <data>/bans.json = { version, updatedAt, bans: [ { username?, uuid?, hwid?, reason?, at? } ] }
//   - username casa a conta (offline OU social) pelo NICK, sem diferenciar maiúsculas;
//   - uuid casa a conta offline pelo UUID canônico (com ou sem hífens);
//   - hwid casa o HARDWARE (hash sha256 de SMBIOS UUID + serial da placa + serial do
//     disco, calculado no launcher e enviado em X-Reality-Device): vale mesmo com
//     nick novo, conta nova e .reality apagada;
//   - reason é o motivo mostrado ao jogador e no webhook do Guard.
// Público: GET /api/bans entrega SÓ a lista (nick/uuid/motivo) — o launcher usa
// pra bloquear o launch e mostrar o aviso. Nada sensível mora aqui.
// Admin (requireAdmin):  POST /api/admin/bans { username?, uuid?, reason? } adiciona/atualiza;
//                        DELETE /api/admin/bans { username?|uuid? } (ou ?username=) remove.
// Arquivo ausente/inválido nunca derruba o servidor: semeia com a lista padrão.
const BANS_FILE = path.join(DATA_DIR, 'bans.json');
const BANS_CACHE_MS = 10 * 1000;
const BANS_MAX_ENTRIES = 5000;
const BANS_DEFAULT = [
  { username: 'halseixit2', uuid: '834c3dc0-d82e-340f-8270-169edfcbab1c', reason: 'fraude de moedas (coins editado no config.json) + historico de cheats' },
  { username: 'nuli', reason: 'fraude de moedas / uso de cheats (conta do Discord: nuli)' }
];
let bansCache = { at: 0, data: null };

function bansSanitizeEntry(bruto) {
  if (!bruto || typeof bruto !== 'object' || Array.isArray(bruto)) return null;
  const username = String(bruto.username || '').replace(/[\r\n\t]/g, ' ').trim().slice(0, 32);
  const uuidBruto = String(bruto.uuid || '').trim().slice(0, 64);
  // HWID (ban por placa-mae): hash sha256 (64 hex) calculado no launcher em cima do
  // hardware (SMBIOS UUID + serial da placa + serial do disco). NUNCA e o serial cru.
  const hwidBruto = String(bruto.hwid || '').trim().toLowerCase().slice(0, 64);
  const hwid = /^[a-f0-9]{16,64}$/.test(hwidBruto) ? hwidBruto : '';
  // hwid2/comps (device v2): o CONJUNTO de sinais permite casar o ban com 1
  // sinal trocado (placa nova, BIOS atualizada...). Nunca sao seriais crus.
  const hwid2Bruto = String(bruto.hwid2 || '').trim().toLowerCase().slice(0, 64);
  const hwid2 = /^[a-f0-9]{64}$/.test(hwid2Bruto) ? hwid2Bruto : '';
  const compsBruto = Array.isArray(bruto.comps) ? bruto.comps : [];
  const comps = compsBruto.map((c) => String(c || '').trim().toLowerCase()).filter((c) => DEVICE_COMP_RE.test(c)).slice(0, DEVICE_V2_MAX_COMPS);
  const reason = String(bruto.reason || 'banido').replace(/[\r\n\t]/g, ' ').trim().slice(0, 200) || 'banido';
  const at = Math.max(0, Math.floor(Number(bruto.at) || Date.now()));
  if (!username && !uuidBruto && !hwid && !hwid2) return null;
  return {
    username,
    uuid: /^[0-9a-fA-F-]{32,36}$/.test(uuidBruto) ? normalizeUuid(uuidBruto) : '',
    hwid,
    hwid2,
    comps,
    reason,
    at
  };
}

function bansDefaultFile() {
  const agora = Date.now();
  return {
    version: 1,
    updatedAt: new Date(agora).toISOString(),
    bans: BANS_DEFAULT.map((b) => bansSanitizeEntry({ ...b, at: agora })).filter(Boolean)
  };
}

function writeBansFile(dados) {
  ensureData();
  const tempFile = `${BANS_FILE}.tmp`;
  fs.writeFileSync(tempFile, JSON.stringify(dados, null, 2), 'utf-8');
  fs.renameSync(tempFile, BANS_FILE); // troca atômica (igual ao manifesto)
  bansCache = { at: Date.now(), data: dados };
  return dados;
}

function readBans(force) {
  const agora = Date.now();
  if (!force && bansCache.data && agora - bansCache.at < BANS_CACHE_MS) return bansCache.data;
  let bruto = null;
  try {
    if (fs.existsSync(BANS_FILE)) bruto = JSON.parse(fs.readFileSync(BANS_FILE, 'utf-8'));
  } catch (_) {
    bruto = null; // arquivo corrompido => recomeça da lista padrão
  }
  let dados;
  if (bruto && typeof bruto === 'object' && Array.isArray(bruto.bans)) {
    dados = {
      version: Math.max(1, Math.floor(Number(bruto.version) || 1)),
      updatedAt: typeof bruto.updatedAt === 'string' ? bruto.updatedAt.slice(0, 40) : new Date().toISOString(),
      bans: bruto.bans.map(bansSanitizeEntry).filter(Boolean).slice(0, BANS_MAX_ENTRIES)
    };
  } else {
    // Primeiro boot (ou arquivo inválido): grava a lista padrão — o bloqueio vale
    // desde o primeiro start e o dono só edita o data/bans.json depois.
    dados = bansDefaultFile();
    try { writeBansFile(dados); } catch (_) { /* não deixa o boot quebrar por isso */ }
  }
  bansCache = { at: agora, data: dados };
  return dados;
}

function bansUuidEq(a, b) {
  const na = normalizeUuid(a).replace(/-/g, '').toLowerCase();
  const nb = normalizeUuid(b).replace(/-/g, '').toLowerCase();
  return na.length === 32 && nb.length === 32 && na === nb;
}

/** HWID do request (X-Reality-Device do launcher; sha256 hex = 64 chars). */
function deviceFromRequest(req) {
  try { return String((req && req.headers && req.headers['x-reality-device']) || '').trim().toLowerCase().slice(0, 64); } catch (_) { return ''; }
}

// ---------- Device v2: HWID composto + componentes + assinatura (launcher 1.6.73+) ----------
// O launcher NOVO manda, alem do X-Reality-Device (v1, mantido por compatibilidade
// com 1.6.71/1.6.72 e com os bans ja aplicados):
//   X-Reality-Device-V2    = hash composto (SMBIOS UUID + placa + BIOS + discos + MachineGuid)
//   X-Reality-Device-Comps = "k:hash32,k:hash32,..." (hashes dos SINAIS de hardware)
//   X-Reality-Device-Ts    = epoch ms
//   X-Reality-Device-Sig   = HMAC-SHA256(segredo, v1|v2|comps|ts)
// LIMITE HONESTO: a chave do HMAC vive no launcher, que e PUBLICO (o app.asar e
// extraivel e o source ja circula). A assinatura e um SPEED BUMP contra forja
// casual; a defesa REAL e server-side: ban por CONJUNTO de componentes (tolerando
// 1 sinal trocado), mapa de device e anomalia de muitas contas no mesmo hardware.
const DEVICE_HMAC_SECRET = String(process.env.DEVICE_HMAC_SECRET || '').trim();
const DEVICE_TS_WINDOW_MS = 15 * 60 * 1000;
const DEVICE_V2_MAX_COMPS = 12;
const DEVICE_COMP_RE = /^[a-z0-9_]{1,12}:[a-f0-9]{32}$/;

function devicePayloadFromRequest(req) {
  try {
    const h = (req && req.headers) || {};
    const v1 = String(h['x-reality-device'] || '').trim().toLowerCase().slice(0, 64);
    const v2 = String(h['x-reality-device-v2'] || '').trim().toLowerCase().slice(0, 64);
    const compsBruto = String(h['x-reality-device-comps'] || '').trim().toLowerCase();
    const ts = Math.floor(Number(h['x-reality-device-ts']) || 0);
    const sig = String(h['x-reality-device-sig'] || '').trim().toLowerCase().slice(0, 64);
    const comps = compsBruto.split(',').map((s) => s.trim()).filter((s) => DEVICE_COMP_RE.test(s)).slice(0, DEVICE_V2_MAX_COMPS);
    const out = {
      v1: /^[a-f0-9]{64}$/.test(v1) ? v1 : '',
      v2: /^[a-f0-9]{64}$/.test(v2) ? v2 : '',
      comps,
      ts,
      sig: /^[a-f0-9]{64}$/.test(sig) ? sig : '',
      signed: false
    };
    if (DEVICE_HMAC_SECRET && out.v1 && out.sig && out.ts && Math.abs(Date.now() - out.ts) <= DEVICE_TS_WINDOW_MS) {
      const msg = [out.v1, out.v2, out.comps.join(','), String(out.ts)].join('|');
      const esperado = crypto.createHmac('sha256', DEVICE_HMAC_SECRET).update(msg).digest('hex');
      try { out.signed = crypto.timingSafeEqual(Buffer.from(esperado, 'hex'), Buffer.from(out.sig, 'hex')); } catch (_) { out.signed = false; }
    }
    return out;
  } catch (_) { return { v1: '', v2: '', comps: [], ts: 0, sig: '', signed: false }; }
}

/** Casa o CONJUNTO de componentes do cliente com o de um ban (tolera 1 sinal trocado). */
function compsMatch(compsCliente, compsBan) {
  try {
    const a = Array.isArray(compsCliente) ? compsCliente : [];
    const b = Array.isArray(compsBan) ? compsBan : [];
    if (a.length < 2 || b.length < 2) return false;
    const setB = new Set(b);
    const comuns = a.filter((c) => setB.has(c)).length;
    const menor = Math.min(a.length, b.length);
    return comuns >= 2 && comuns * 2 >= menor; // metade do conjunto menor ou mais
  } catch (_) { return false; }
}

/** Casa uma identidade ({ username?, uuid?, key?, hwid? }) contra a lista negra. */
function banMatch(alvo) {
  try {
    const nick = String((alvo && alvo.username) || '').trim().toLowerCase();
    const id = String((alvo && alvo.uuid) || '').trim();
    const chave = String((alvo && alvo.key) || '').trim().toLowerCase();
    const hw = String((alvo && alvo.hwid) || '').trim().toLowerCase();
    const hw2 = String((alvo && alvo.hwid2) || '').trim().toLowerCase();
    const compsAlvo = Array.isArray(alvo && alvo.comps) ? alvo.comps : [];
    for (const b of readBans().bans) {
      if (b.username && nick && b.username.toLowerCase() === nick) return Object.assign({}, b, { matched: 'username' });
      if (b.uuid && id && bansUuidEq(b.uuid, id)) return Object.assign({}, b, { matched: 'uuid' });
      if (b.uuid && chave && chave === 'offline:' + normalizeUuid(b.uuid).toLowerCase()) return Object.assign({}, b, { matched: 'uuid' });
      // Ban por HWID (placa-mae): v1 exato = o caso normal; v2 e o CONJUNTO de
      // componentes cobrem hardware parcialmente alterado (1 sinal trocado).
      if (b.hwid && /^[a-f0-9]{16,64}$/.test(hw) && b.hwid === hw) return Object.assign({}, b, { matched: 'hwid' });
      if (b.hwid2 && /^[a-f0-9]{64}$/.test(hw2) && b.hwid2 === hw2) return Object.assign({}, b, { matched: 'hwid2' });
      if (Array.isArray(b.comps) && b.comps.length >= 2 && compsAlvo.length >= 2 && compsMatch(compsAlvo, b.comps)) {
        return Object.assign({}, b, { matched: 'hwid-partial' });
      }
    }
  } catch (_) { /* lista indisponível nunca libera nem derruba: sem match */ }
  return null;
}

// Aviso no webhook quando um HWID BANIDO aparece de novo (dedupe por hwid).
const hwidHitDedupe = new Map(); // hwid -> último aviso (ms)
const HWID_HIT_DEDUPE_MS = 10 * 60 * 1000;
function banNotifyHwidHit(ban, info) {
  try {
    const hwid = String((ban && ban.hwid) || '');
    if (!hwid) return;
    const agora = Date.now();
    if (agora - (hwidHitDedupe.get(hwid) || 0) < HWID_HIT_DEDUPE_MS) return;
    hwidHitDedupe.set(hwid, agora);
    if (hwidHitDedupe.size > 500) {
      for (const [k, t] of hwidHitDedupe) { if (agora - t > HWID_HIT_DEDUPE_MS) hwidHitDedupe.delete(k); }
    }
    const url = guardWebhookUrl();
    if (!url) return;
    const nome = String((info && info.username) || '').slice(0, 32) || '(sem nick)';
    const uuid = String((info && info.uuid) || '').slice(0, 40) || '(sem uuid)';
    guardWebhookPost(url, {
      username: 'Reality Guard',
      embeds: [{
        title: '🚫 HWID BANIDO tentou usar o launcher',
        color: 0xB00020,
        fields: [
          { name: 'Jogador', value: '`' + nome + '`', inline: true },
          { name: 'UUID', value: '`' + uuid + '`', inline: true },
          { name: 'HWID', value: '`' + hwid.slice(0, 24) + '…`', inline: true },
          { name: 'Como casou', value: '`' + String((ban && ban.matched) || 'hwid') + '`', inline: true },
          { name: 'Motivo do ban', value: String((ban && ban.reason) || 'banido').slice(0, 180), inline: false },
          { name: 'Horário (Brasília)', value: guardBrasiliaTime(agora), inline: true }
        ],
        footer: { text: 'ban por hardware (data/bans.json)' }
      }]
    }).catch(() => {});
  } catch (_) { /* aviso nunca quebra a checagem */ }
}

function banPublicEntry(b) {
  const out = { username: (b && b.username) || '', uuid: (b && b.uuid) || '', reason: (b && b.reason) || 'banido', at: (b && b.at) || 0 };
  if (b && b.hwid) out.hwid = b.hwid; // hash, nunca o serial cru
  // Como o match aconteceu (username/uuid/hwid/hwid2/hwid-partial) — visível só
  // nas respostas 403 de bloqueio; a LISTA pública continua sem esse campo.
  if (b && b.matched) out.matched = String(b.matched);
  return out;
}

function banBlockBody(ban) {
  return {
    ok: false,
    error: 'banned',
    message: 'Voce foi banido - fraude/uso de cheats - fale no Discord.',
    ban: Object.assign(banPublicEntry(ban), (ban && ban.matched) ? { matched: String(ban.matched) } : {})
  };
}

/** Identidade a partir do coinsIdentity/social (name + key offline:/social:). */
function banIdentityFromCoins(ident) {
  if (!ident) return null;
  const key = String(ident.key || '');
  return {
    username: ident.name || '',
    uuid: ident.kind === 'offline' && key.startsWith('offline:') ? key.slice(8) : '',
    key
  };
}

/** Checa a lista negra pro request: identidade resolvida + username/uuid/hwid do corpo/headers. */
function banCheckRequest(req, ident) {
  try {
    const dev = devicePayloadFromRequest(req);
    const hwidReq = dev.v1;
    const alvos = [];
    const doIdent = banIdentityFromCoins(ident);
    if (doIdent) {
      doIdent.hwid = hwidReq;
      doIdent.hwid2 = dev.v2;
      doIdent.comps = dev.comps;
      if (doIdent.username || doIdent.uuid || hwidReq) alvos.push(doIdent);
    }
    const body = (req && req.body) || {};
    const username = String(body.username || body.name || req.headers['x-reality-name'] || '').trim();
    const uuid = String(body.uuid || req.headers['x-reality-uuid'] || '').trim();
    const hwidBody = String(body.hwid || hwidReq || '').trim();
    if (username || uuid || hwidBody) {
      alvos.push({ username, uuid, hwid: hwidBody, hwid2: dev.v2, comps: dev.comps, key: uuid ? 'offline:' + normalizeUuid(uuid).toLowerCase() : '' });
    }
    for (const alvo of alvos) {
      const banido = banMatch(alvo);
      if (banido) {
        if (banido.matched === 'hwid') banNotifyHwidHit(banido, { username, uuid });
        return banido;
      }
    }
  } catch (_) {}
  return null;
}

/** GET /api/bans — lista negra pública pro launcher (nick/uuid/motivo). */
app.get('/api/bans', (req, res) => {
  try {
    res.setHeader('Cache-Control', 'no-store');
    if (!rateLimit(clientKey(req), 'bans-get', 120, 60000)) {
      return res.status(429).json({ ok: false, error: 'too_many_requests' });
    }
    const dados = readBans();
    res.json({
      ok: true,
      version: dados.version,
      updatedAt: dados.updatedAt,
      count: dados.bans.length,
      bans: dados.bans.map(banPublicEntry)
    });
  } catch (_) {
    try { res.status(500).json({ ok: false, error: 'bans_read_failed' }); } catch (_2) {}
  }
});

// ---------- Público ----------

app.get('/', (_req, res) => {
  res.type('html').send(
    '<!doctype html><html><body style="font-family:sans-serif;background:#0b0f14;color:#e8eef7;padding:2rem">' +
    '<h1>Reality Client Backend</h1>' +
    '<p>Online.</p>' +
    '<ul>' +
    '<li><a style="color:#7dd3fc" href="/health">/health</a></li>' +
    '<li><a style="color:#7dd3fc" href="/api/manifest">/api/manifest</a></li>' +
    '<li><a style="color:#7dd3fc" href="/api/update">/api/update</a></li>' +
    '<li><a style="color:#7dd3fc" href="/api/bans">/api/bans</a></li>' +
    '</ul></body></html>'
  );
});

app.get('/health', (_req, res) => {
  res.json({ ok: true, service: 'reality-client-backend' });
});

/**
 * Presença de jogadores usando o Reality Client (pro ícone no tab list do
 * mod cliente). Sem banco de dados — só um mapa em memória com expiração.
 * O mod manda um heartbeat a cada ~20s; se parar de mandar, expira sozinho.
 */
const onlineRealityUsers = new Map(); // uuid -> { name, lastSeen }

/** UUID canónico com hífens (o TAB do Minecraft usa sempre este formato). */
function normalizeUuid(u) {
  const h = String(u || '').toLowerCase().replace(/[^0-9a-f]/g, '');
  if (h.length !== 32) return String(u || '').toLowerCase().trim();
  return h.slice(0, 8) + '-' + h.slice(8, 12) + '-' + h.slice(12, 16) + '-' + h.slice(16, 20) + '-' + h.slice(20);
}


const PRESENCE_TTL_MS = 5 * 60 * 1000; // 5 min — evita sumir se o heartbeat atrasar

// Antes, a limpeza de quem expirou só rolava quando alguém chamava
// GET /api/presence/online. Se nada chamasse essa rota por um tempo (ex:
// backend reiniciado e só chegando heartbeats), o mapa cresceria pra sempre.
// Essa varredura por tempo garante limpeza mesmo sem ninguém pedindo a lista.
setInterval(() => {
  const now = Date.now();
  for (const [uuid, info] of onlineRealityUsers.entries()) {
    if (now - info.lastSeen > PRESENCE_TTL_MS) onlineRealityUsers.delete(uuid);
  }
}, 30 * 1000).unref();

// ---------- F07: autenticacao da presenca ----------
// Antes: qualquer cliente mandava {uuid,name,capeId} e o indice era reescrito —
// dava para RENOMEAR outro jogador e para pendurar uma capa PAGA/exclusiva num
// uuid que nunca resgatou o codigo. Agora:
//   1) TOKEN SOCIAL (Authorization: Bearer <token>) => identidade DERIVADA DO
//      TOKEN: o nick vem da conta e o uuid fica AMARRADO a conta no primeiro
//      heartbeat verificado. Body com uuid/nome de outra pessoa => 403.
//   2) HMAC POR DISPOSITIVO (X-Reality-Presence-Sig + X-Reality-Presence-Ts,
//      chave PRESENCE_HMAC_SECRET/DEVICE_HMAC_SECRET) => heartbeat assinado.
//   3) Sem nenhum dos dois => heartbeat NAO VERIFICADO: so pode CRIAR/REFRESCAR a
//      propria entrada; nao troca o nome de entrada existente nem o de entrada
//      verificada, e CAPA EXCLUSIVA/PAGA so entra se a CONTA possui
//      (ownedCapes do data/coins.json) — o resto e ignorado.
//   4) Carimbo do servidor: 1 heartbeat por uuid a cada PRESENCE_MIN_INTERVAL_MS
//      e teto por IP; o indice guarda verified=true/false e o launcher/mod podem
//      filtrar (?verified=1).
const PRESENCE_MIN_INTERVAL_MS = Math.max(3_000, Math.floor(Number(process.env.PRESENCE_MIN_INTERVAL_MS) || 4_000));
const PRESENCE_IP_MAX_PER_MIN = Math.max(30, Math.floor(Number(process.env.PRESENCE_IP_MAX_PER_MIN) || 240));
const PRESENCE_UNVERIFIED_MAX = Math.max(100, Math.floor(Number(process.env.PRESENCE_UNVERIFIED_MAX) || 2000));
const PRESENCE_HMAC_SECRET = String(process.env.PRESENCE_HMAC_SECRET || process.env.DEVICE_HMAC_SECRET || '').trim();
const presenceLastBeat = new Map(); // uuid -> ultimo heartbeat aceito
setInterval(() => {
  const agora = Date.now();
  for (const [k, t] of presenceLastBeat) { if (agora - t > 30 * 60 * 1000) presenceLastBeat.delete(k); }
}, 5 * 60 * 1000).unref();

/**
 * F07 — capa PROTEGIDA = qualquer capa do sistema de posse do produto:
 *  - capas de CODIGO (exclusivas): COIN_CAPE_EXCLUSIVE
 *  - capas de LOJA (compradas com moedas): COIN_CAPE_PRICES + COIN_CAPE_RETIRED
 *  - capas TRAVADAS por codigo no launcher (LOCKED_CAPES do redeemCatalog.js):
 *    reality_bolt, capa_creator_reality, capa_brmc, capa_mundomc
 * Uma capa protegida so entra na PRESENCA se a CONTA do uuid a possui
 * (ownedCapes). Capa fora dessa lista e custom/local e continua livre.
 */
const COIN_CAPE_LOCKED_CODIGO = ['reality_bolt', 'capa_creator_reality', 'capa_brmc', 'capa_mundomc'];
function capeIsProtected(id) {
  const k = String(id || '').trim().toLowerCase();
  if (!k) return false;
  if (COIN_CAPE_EXCLUSIVE[k]) return true;
  if (COIN_CAPE_PRICES[k]) return true;
  if (Array.isArray(COIN_CAPE_RETIRED) && COIN_CAPE_RETIRED.includes(k)) return true;
  return COIN_CAPE_LOCKED_CODIGO.includes(k);
}

/** (compat) — capa exclusiva de codigo. */
function capeIsExclusive(id) {
  return !!COIN_CAPE_EXCLUSIVE[id];
}

/**
 * Capas da conta que ainda VALEM: tira as expiradas (prêmios do TOP TEMPO duram
 * 30 dias — `capeExpiry[capeId] = timestamp`; sem entrada = vale para sempre).
 */
function capesVivasDaConta(acc) {
  const lista = Array.isArray(acc && acc.ownedCapes) ? acc.ownedCapes : [];
  const exp = (acc && acc.capeExpiry) || {};
  const agora = Date.now();
  return lista.filter((id) => {
    const e = Number(exp[id]);
    return !Number.isFinite(e) || e <= 0 || e > agora;
  });
}

/** A CONTA possui essa capa? (fonte de verdade: ownedCapes do data/coins.json) */
function accountOwnsCape(identKey, capeId) {
  if (!identKey) return false;
  try {
    const dados = readCoins();
    const acc = dados && dados.accounts ? dados.accounts[identKey] : null;
    return !!(acc && capesVivasDaConta(acc).includes(capeId));
  } catch (_) {
    return false;
  }
}

/**
 * F07 — a posse da capa e da CONTA, nao do uuid solto. Chaves possiveis para um
 * uuid: `offline:<uuid>` (conta offline, mesma chave do redeem/coins) e
 * `social:<id>` quando o uuid esta amarrado a uma conta social (bindUuid).
 */
function capeOwnedByUuid(uuid, capeId) {
  try {
    const dados = readCoins();
    const contas = (dados && dados.accounts) || {};
    const chaves = ['offline:' + uuid];
    try {
      const u = social.findUserByUuid && social.findUserByUuid(uuid);
      if (u && u.id) chaves.push('social:' + String(u.id));
    } catch (_) {}
    return chaves.some((k) => {
      const a = contas[k];
      return !!(a && capesVivasDaConta(a).includes(capeId));
    });
  } catch (_) {
    return false;
  }
}

/** HMAC do heartbeat (opcional, quando PRESENCE_HMAC_SECRET/DEVICE_HMAC_SECRET existe). */
function presenceHmacOk(req, uuid, name, capeId) {
  if (!PRESENCE_HMAC_SECRET) return false;
  const sig = String(req.headers['x-reality-presence-sig'] || '').trim().toLowerCase();
  const ts = Number(req.headers['x-reality-presence-ts'] || 0);
  if (!sig || !Number.isFinite(ts) || Math.abs(Date.now() - ts) > 5 * 60 * 1000) return false;
  const msg = [normalizeUuid(uuid), String(name || ''), String(capeId || ''), String(Math.floor(ts))].join('|');
  let esperado = '';
  try {
    esperado = crypto.createHmac('sha256', PRESENCE_HMAC_SECRET).update(msg).digest('hex');
  } catch (_) {
    return false;
  }
  try {
    return crypto.timingSafeEqual(Buffer.from(sig, 'utf8'), Buffer.from(esperado, 'utf8'));
  } catch (_) {
    return false;
  }
}

app.post('/api/presence/heartbeat', (req, res) => {
  const body = req.body || {};
  let uuid = String(body.uuid || '').trim();
  let name = String(body.name || body.username || '').trim().slice(0, 32);
  let capeId = body.capeId != null ? String(body.capeId).slice(0, 64) : null;

  // --- (1) token social: identidade DERIVADA DO TOKEN (F06/F07) ---
  const authHeader = String(req.headers.authorization || '');
  const tokenRaw = /^Bearer\s+/i.test(authHeader) ? authHeader.replace(/^Bearer\s+/i, '').trim() : '';
  let tokenUser = null;
  if (tokenRaw) {
    try { tokenUser = social.findUserByToken(tokenRaw); } catch (_) { tokenUser = null; }
    if (!tokenUser) return res.status(401).json({ ok: false, error: 'invalid_token' });
  }

  let verified = false;
  let source = 'anon';
  let identKey = null;

  if (tokenUser) {
    const bound = String(tokenUser.uuid || '').trim();
    if (bound) {
      if (uuid && normalizeUuid(uuid) !== normalizeUuid(bound)) {
        return res.status(403).json({ ok: false, error: 'identity_mismatch' });
      }
      uuid = bound;
    } else if (!/^[0-9a-fA-F-]{32,36}$/.test(uuid)) {
      return res.status(400).json({ ok: false, error: 'invalid_uuid' });
    } else {
      // amarra o uuid a conta no primeiro heartbeat verificado
      try { social.bindUuid(tokenRaw, normalizeUuid(uuid)); } catch (_) {}
    }
    name = String(tokenUser.username || '').trim().slice(0, 32) || name;
    verified = true;
    source = 'social';
    identKey = 'social:' + String(tokenUser.id || '').slice(0, 70);
  } else if (presenceHmacOk(req, uuid, name, capeId)) {
    verified = true;
    source = 'hmac';
  }

  if (!/^[0-9a-fA-F-]{32,36}$/.test(uuid)) {
    return res.status(400).json({ error: 'invalid_uuid' });
  }
  // SEGURANCA: name e capeId viram nome de arquivo nos launchers (cape_overrides) - valida aqui tambem.
  if (name && !/^[A-Za-z0-9_]{1,16}$/.test(name)) {
    return res.status(400).json({ error: 'invalid_name' });
  }
  if (capeId != null && capeId !== '' && !/^[a-z0-9_]{1,32}$/i.test(String(capeId))) {
    return res.status(400).json({ error: 'invalid_cape' });
  }
  const key = normalizeUuid(uuid);
  // BAN: nick/uuid/HWID banido nao entra na presenca (nem renova lastSeen).
  const banPresence = banCheckRequest(req, null);
  if (banPresence) {
    return res.status(403).json({ ok: false, error: 'banned', ban: banPublicEntry(banPresence) });
  }
  if (!rateLimit(clientKey(req), 'presence-ip', PRESENCE_IP_MAX_PER_MIN, 60000)) {
    return res.status(429).json({ ok: false, error: 'too_many_heartbeats_ip' });
  }
  const agora = Date.now();
  const ultimoBeat = presenceLastBeat.get(key) || 0;
  if (agora - ultimoBeat < PRESENCE_MIN_INTERVAL_MS) {
    return res.status(429).json({ ok: false, error: 'too_many_heartbeats', retryInMs: PRESENCE_MIN_INTERVAL_MS - (agora - ultimoBeat) });
  }
  presenceLastBeat.set(key, agora);

  const prev = onlineRealityUsers.get(key) || null;
  // Anti-impersonacao: entrada VERIFICADA so e atualizada por heartbeat verificado;
  // entrada anonima existente nao pode ser RENOMEADA por outro anonimo.
  if (prev && prev.verified === true && !verified) {
    return res.status(401).json({ ok: false, error: 'verified_identity_requires_token' });
  }
  if (prev && !verified && name && prev.name && name !== prev.name) {
    return res.status(403).json({ ok: false, error: 'name_locked' });
  }
  if (!prev && !verified) {
    let naoVerificados = 0;
    for (const info of onlineRealityUsers.values()) if (!info || info.verified !== true) naoVerificados += 1;
    if (naoVerificados >= PRESENCE_UNVERIFIED_MAX) {
      return res.status(429).json({ ok: false, error: 'presence_full' });
    }
  }

  // CAPA server-authoritative: capa PROTEGIDA (codigo/loja/travada no launcher)
  // so entra se a CONTA possui (ownedCapes). Sem posse => mantem a capa anterior
  // (ou null). Capa custom/local continua livre.
  let capeFinal = capeId;
  let capeIgnorada = false;
  if (capeFinal != null && capeFinal !== '' && capeIsProtected(capeFinal)) {
    const dono = (identKey && accountOwnsCape(identKey, capeFinal)) || capeOwnedByUuid(key, capeFinal);
    if (!dono) {
      capeFinal = prev ? (prev.capeId || null) : null;
      capeIgnorada = true;
    }
  }

  try { trackDevice(req, name, key); } catch (_) {}
  onlineRealityUsers.set(key, {
    name: name || (prev && prev.name) || '',
    capeId: capeFinal !== null ? capeFinal : ((prev && prev.capeId) || null),
    lastSeen: agora,
    verified,
    source
  });
  // Persistência em disco (capas entre reinícios curtos do backend)
  try {
    if (typeof presence !== 'undefined' && presence.heartbeat) {
      presence.heartbeat({
        uuid: key,
        username: name || (prev && prev.name) || '',
        capeId: capeFinal !== null ? capeFinal : ((prev && prev.capeId) || null),
        verified
      });
    }
  } catch (_) {}
  res.json({ ok: true, verified, source, uuid: key, name: name || (prev && prev.name) || '', capeId: capeFinal, capeIgnored: capeIgnorada });
});

app.get('/api/presence/online', (req, res) => {
  const now = Date.now();
  const somenteVerificados = String(req.query.verified || '') === '1';
  const list = [];
  for (const [uuid, info] of onlineRealityUsers.entries()) {
    if (now - info.lastSeen <= PRESENCE_TTL_MS) {
      if (somenteVerificados && info.verified !== true) continue;
      list.push({ uuid, name: info.name, capeId: info.capeId || null, verified: info.verified === true, launcher: true });
    } else {
      onlineRealityUsers.delete(uuid);
    }
  }
  // count real + piso de exibição (>= 100) para o contador do launcher
  const real = list.length;
  // count = REAL (mod TAB + launcher). Nada de inflar — senão parece fake.
  res.json({ ok: true, count: real, real, users: list, players: list });
});

/** Consulta por lista de UUIDs (mod in-game) */
app.get('/api/presence', (req, res) => {
  const raw = String(req.query.uuids || '').trim();
  const want = raw ? raw.split(',').map((s) => s.trim().toLowerCase()).filter(Boolean) : [];
  const now = Date.now();
  const list = [];
  for (const [uuid, info] of onlineRealityUsers.entries()) {
    if (now - info.lastSeen > PRESENCE_TTL_MS) {
      onlineRealityUsers.delete(uuid);
      continue;
    }
    const undashed = uuid.replace(/-/g, '');
    const wantNorm = want.map((w) => normalizeUuid(w));
    if (!want.length || wantNorm.includes(uuid) || want.includes(uuid) || want.includes(undashed)) {
      list.push({ uuid, name: info.name, capeId: info.capeId || null, verified: info.verified === true, launcher: true });
    }
  }
  res.json({ ok: true, players: list, users: list });
});

/** Manifesto completo — o launcher puxa isso no boot */
app.get('/api/manifest', (_req, res) => {
  try {
    res.json(readManifest());
  } catch (e) {
    res.status(500).json({ error: 'manifest_read_failed' });
  }
});

/** Feed de update no formato do updateChecker (+ assinatura Ed25519 — F02) */
app.get('/api/update', (_req, res) => {
  try {
    const m = readManifest();
    const assin = manifestSignature();
    if (assin && assin.sig) res.setHeader(MANIFEST_SIG_HEADER, assin.sig);
    res.json({
      version: m.launcher?.latestVersion || '1.0.0',
      url: m.launcher?.downloadUrl || '',
      notes: m.launcher?.notes || '',
      sha256: m.launcher?.sha256 || '',
      size: Number(m.launcher?.size || 0) || 0,
      mandatory: Boolean(m.launcher?.mandatory),
      platforms: m.launcher?.platforms || {},
      // F02: assinatura detached do payload canonico <version>|<url>|<sha256>|<size>
      sig: (assin && assin.sig) || '',
      sigAlg: MANIFEST_ALG,
      sigKeyId: (assin && assin.keyId) || ''
    });
  } catch (e) {
    res.status(500).json({ error: 'update_read_failed' });
  }
});

/** F02: assinatura detached crua (base64), ao lado do manifest.json. */
app.get('/api/manifest.sig', (_req, res) => {
  try {
    const assin = manifestSignature();
    if (!assin || !assin.sig) return res.status(503).json({ error: 'signature_unavailable' });
    res.type('text/plain').send(assin.sig);
  } catch (_) {
    res.status(500).json({ error: 'signature_read_failed' });
  }
});

/** F02: chave publica de verificacao (o launcher embute este base64). */
app.get('/api/pubkey', (_req, res) => {
  try {
    const chaves = loadManifestKeys();
    if (!chaves) return res.status(503).json({ error: 'pubkey_unavailable' });
    res.json({
      ok: true,
      algorithm: MANIFEST_ALG,
      publicKey: chaves.publicB64,
      keyId: chaves.keyId,
      payloadFormat: '<version>|<url>|<sha256>|<size>'
    });
  } catch (_) {
    res.status(500).json({ error: 'pubkey_read_failed' });
  }
});

// ---------- Status público (aditivo — não altera nenhuma rota existente) ----------
// Fonte de dados opcional: <data>/status.json (no VPS: /opt/reality-backend/data/status.json)
//   { manutencao: bool, aviso: string, launcherStatus: 'estavel'|'atualizando'|'manutencao',
//     ultimaAuditoria: string, discord: string }
// Se o arquivo não existir (ou estiver inválido), usa os padrões e segue funcionando.
const STATUS_FILE = path.join(DATA_DIR, 'status.json');
const STATUS_PADROES = {
  manutencao: false,
  aviso: '',
  launcherStatus: 'estavel',
  ultimaAuditoria: null,
  discord: ''
};

function lerArquivoStatus() {
  const dados = { ...STATUS_PADROES };
  try {
    if (!fs.existsSync(STATUS_FILE)) return dados;
    const bruto = JSON.parse(fs.readFileSync(STATUS_FILE, 'utf-8'));
    if (!bruto || typeof bruto !== 'object') return dados;
    if (typeof bruto.manutencao === 'boolean') dados.manutencao = bruto.manutencao;
    if (typeof bruto.aviso === 'string') {
      dados.aviso = bruto.aviso.replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, 300);
    }
    if (['estavel', 'atualizando', 'manutencao'].indexOf(bruto.launcherStatus) !== -1) {
      dados.launcherStatus = bruto.launcherStatus;
    }
    if (typeof bruto.ultimaAuditoria === 'string') {
      dados.ultimaAuditoria = bruto.ultimaAuditoria.trim().slice(0, 64) || null;
    }
    if (typeof bruto.discord === 'string') {
      dados.discord = bruto.discord.replace(/[\u0000-\u001f\u007f]/g, ' ').trim().slice(0, 200);
    }
  } catch (_) {
    // Arquivo ausente ou inválido: mantém os padrões. Nunca derruba o servidor.
  }
  return dados;
}

function versaoDoLauncher() {
  try {
    const m = readManifest();
    const v = (m && m.launcher && m.launcher.latestVersion) || (m && m.version) || '1.0.0';
    return String(v).trim().slice(0, 32) || '1.0.0';
  } catch (_) {
    return '1.0.0';
  }
}

function launcherInfoAtualizadaEm() {
  try {
    const m = readManifest();
    const quando = m && m.updatedAt;
    if (typeof quando === 'string' && Number.isFinite(Date.parse(quando))) {
      return new Date(Date.parse(quando)).toISOString();
    }
  } catch (_) {}
  return new Date().toISOString();
}

function discordDoManifest() {
  try {
    const m = readManifest();
    const d = (m && m.discord) || {};
    const link = String(d.reality || d.kowa || '').trim();
    return /^https?:\/\//i.test(link) ? link.slice(0, 200) : null;
  } catch (_) {
    return null;
  }
}

function jogadoresOnlineAgora() {
  try {
    const agora = Date.now();
    let total = 0;
    for (const info of onlineRealityUsers.values()) {
      if (info && agora - Number(info.lastSeen || 0) <= PRESENCE_TTL_MS) total += 1;
    }
    return total;
  } catch (_) {
    return 0;
  }
}

function montarStatusPublico() {
  const arquivo = lerArquivoStatus();
  const manutencaoAtiva = arquivo.manutencao === true;
  let statusLauncher = arquivo.launcherStatus || 'estavel';
  if (manutencaoAtiva) statusLauncher = 'manutencao';
  if (['estavel', 'atualizando', 'manutencao'].indexOf(statusLauncher) === -1) statusLauncher = 'estavel';

  let uptimeSegundos = 0;
  try { uptimeSegundos = Math.max(0, Math.round(process.uptime())); } catch (_) {}
  let memoriaMb = 0;
  try { memoriaMb = Math.round(process.memoryUsage().rss / 1024 / 1024); } catch (_) {}

  const agora = new Date().toISOString();
  return {
    ok: true,
    launcher: {
      versao: versaoDoLauncher(),
      status: statusLauncher,
      atualizadoEm: launcherInfoAtualizadaEm()
    },
    servidor: {
      status: manutencaoAtiva ? 'manutencao' : 'online',
      uptimeSegundos,
      agora,
      memoriaMb
    },
    jogadores: { online: jogadoresOnlineAgora() },
    manutencao: {
      ativa: manutencaoAtiva,
      aviso: manutencaoAtiva ? (arquivo.aviso || 'Manutenção em andamento. Voltamos em breve.') : null
    },
    seguranca: {
      ultimaAuditoria: arquivo.ultimaAuditoria || null,
      observacao: 'Rate limit ativo, CORS restrito e headers de segurança aplicados (nosniff e X-Frame-Options).'
    },
    links: {
      discord: arquivo.discord || discordDoManifest() || null,
      site: null
    }
  };
}

function renderStatusPage() {
  let inicial = { ok: false };
  try { inicial = montarStatusPublico(); } catch (_) {}
  const inicialJson = JSON.stringify(inicial)
    .replace(/</g, '\\u003c')
    .replace(/\u2028/g, '\\u2028')
    .replace(/\u2029/g, '\\u2029');

  return `<!doctype html>
<html lang="pt-BR">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<meta name="color-scheme" content="dark">
<meta name="robots" content="index,follow">
<title>Status — Reality Client</title>
<style>
:root{--bg:#0d0f14;--card:#161a22;--border:#232a36;--txt:#e8eef7;--muted:#8b95a7;--ok:#3ddc84;--warn:#ffcf4d;--err:#ff5c5c;--link:#7dd3fc}
*{box-sizing:border-box}
html,body{margin:0;padding:0}
body{background:var(--bg);color:var(--txt);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Ubuntu,Cantarell,"Helvetica Neue",Arial,sans-serif;line-height:1.5;-webkit-font-smoothing:antialiased}
.wrap{max-width:900px;margin:0 auto;padding:26px 18px 44px}
header{display:flex;align-items:center;gap:10px;margin:2px 0 18px;flex-wrap:wrap}
.logo{width:11px;height:11px;border-radius:3px;background:var(--ok);box-shadow:0 0 0 4px rgba(61,220,132,.12);flex:0 0 auto}
header h1{margin:0;font-size:16px;font-weight:650;letter-spacing:.2px}
header .tag{color:var(--muted);font-size:13px}
.hero{position:relative;background:var(--card);border:1px solid var(--border);border-radius:18px;padding:26px 24px 22px;margin-bottom:14px;overflow:hidden}
.hero::before{content:"";position:absolute;top:0;bottom:0;left:0;width:4px;background:var(--ok)}
.hero.state-atualizando::before,.hero.state-manutencao::before{background:var(--warn)}
.hero.state-falha::before{background:var(--err)}
.badge{display:flex;align-items:center;gap:10px;font-size:clamp(22px,4.6vw,30px);font-weight:700;letter-spacing:1.5px;color:var(--ok)}
.hero.state-atualizando .badge,.hero.state-manutencao .badge{color:var(--warn)}
.hero.state-falha .badge{color:var(--err)}
.pulse{width:11px;height:11px;border-radius:50%;background:currentColor;box-shadow:0 0 0 0 currentColor;animation:pulse 2.2s ease-out infinite;flex:0 0 auto}
@keyframes pulse{0%{box-shadow:0 0 0 0 currentColor;opacity:1}70%{box-shadow:0 0 0 11px transparent;opacity:.85}100%{box-shadow:0 0 0 0 transparent;opacity:1}}
.desc{color:#c3ccda;font-size:15px;margin:10px 0 0;max-width:64ch}
.verificado{color:var(--muted);font-size:12.5px;margin:10px 0 0}
.aviso{background:rgba(255,207,77,.08);border:1px solid rgba(255,207,77,.35);color:#ffe6a8;border-radius:12px;padding:12px 16px;margin:0 0 14px;font-size:14px}
.aviso.oculto{display:none}
.grid{display:grid;grid-template-columns:repeat(auto-fit,minmax(212px,1fr));gap:12px}
.card{background:var(--card);border:1px solid var(--border);border-radius:14px;padding:15px 16px;display:flex;flex-direction:column;gap:4px}
.card h2{margin:0;font-size:11.5px;font-weight:600;letter-spacing:.9px;text-transform:uppercase;color:var(--muted)}
.valor{margin:2px 0 0;font-size:20px;font-weight:650;letter-spacing:.2px;word-break:break-word}
.sub{margin:0;font-size:12.5px;color:var(--muted);word-break:break-word}
a{color:var(--link);text-decoration:none}
a:hover{text-decoration:underline}
a.indisponivel{color:var(--muted);pointer-events:none}
footer{margin-top:22px;text-align:center;color:var(--muted);font-size:12.5px}
noscript{display:block;margin-top:12px;color:var(--muted);font-size:13px}
@media (max-width:560px){.wrap{padding:18px 14px 36px}.hero{padding:20px 18px 18px}}
@media (max-width:420px){.grid{grid-template-columns:1fr}}
</style>
</head>
<body>
<div class="wrap">
  <header>
    <span class="logo" aria-hidden="true"></span>
    <h1>Reality Client</h1>
    <span class="tag">· Status do serviço</span>
  </header>

  <section class="hero" id="hero">
    <div class="badge"><span class="pulse" aria-hidden="true"></span><span id="estado-geral">—</span></div>
    <p class="desc" id="estado-descricao">Carregando status…</p>
    <p class="verificado" id="verificado-em">—</p>
    <noscript>Ative o JavaScript para ver o status atualizado automaticamente.</noscript>
  </section>

  <div class="aviso oculto" id="aviso-manutencao"><strong>Aviso:</strong> <span id="aviso-texto"></span></div>

  <section class="grid">
    <article class="card">
      <h2>Versão do launcher</h2>
      <p class="valor" id="versao-launcher">—</p>
      <p class="sub" id="launcher-atualizado">—</p>
    </article>
    <article class="card">
      <h2>Servidor</h2>
      <p class="valor" id="servidor-status">—</p>
      <p class="sub" id="servidor-memoria">—</p>
    </article>
    <article class="card">
      <h2>Uptime</h2>
      <p class="valor" id="uptime">—</p>
      <p class="sub">Desde o último reinício do backend</p>
    </article>
    <article class="card">
      <h2>Jogadores online</h2>
      <p class="valor" id="jogadores-online">—</p>
      <p class="sub">Usando o Reality Client agora</p>
    </article>
    <article class="card">
      <h2>Data e hora</h2>
      <p class="valor" id="data-hora">—</p>
      <p class="sub">Horário de Brasília (America/Sao_Paulo)</p>
    </article>
    <article class="card">
      <h2>Segurança</h2>
      <p class="valor" id="seguranca-auditoria">—</p>
      <p class="sub" id="seguranca-observacao">—</p>
    </article>
    <article class="card">
      <h2>Links</h2>
      <p class="valor"><a id="link-discord" class="indisponivel">Não configurado</a></p>
      <p class="sub">Site: <span id="link-site">Em breve</span></p>
    </article>
  </section>

  <footer>Atualizado automaticamente a cada 30 segundos.</footer>
</div>
<script>
var INITIAL_STATUS = ${inicialJson};
</script>
<script>
(function () {
  var REFRESH_MS = 30000;
  var ESTADOS = { estavel: 'ESTÁVEL', manutencao: 'MANUTENÇÃO', atualizando: 'ATUALIZANDO' };

  function $(id) { return document.getElementById(id); }
  function texto(id, valor) {
    var el = $(id);
    if (el) el.textContent = (valor === null || valor === undefined || valor === '') ? '—' : String(valor);
  }

  function formatarUptime(seg) {
    seg = Math.max(0, Math.floor(Number(seg) || 0));
    var d = Math.floor(seg / 86400), h = Math.floor((seg % 86400) / 3600), m = Math.floor((seg % 3600) / 60);
    if (d > 0) return d + 'd ' + h + 'h ' + m + 'min';
    if (h > 0) return h + 'h ' + m + 'min';
    if (m > 0) return m + ' min';
    return seg + ' s';
  }

  function formatarHoraBrasilia(valor) {
    var d = valor ? new Date(valor) : new Date();
    if (isNaN(d.getTime())) d = new Date();
    try {
      return new Intl.DateTimeFormat('pt-BR', {
        timeZone: 'America/Sao_Paulo',
        day: '2-digit', month: '2-digit', year: 'numeric',
        hour: '2-digit', minute: '2-digit', second: '2-digit'
      }).format(d);
    } catch (e) {
      try { return d.toLocaleString('pt-BR'); } catch (e2) { return '—'; }
    }
  }

  function linkSeguro(url) {
    if (typeof url !== 'string') return null;
    var t = url.trim();
    return /^https?:\\/\\//i.test(t) ? t : null;
  }

  function descricaoPara(status, aviso) {
    if (status === 'manutencao') return aviso || 'Manutenção em andamento. Voltamos em breve.';
    if (status === 'atualizando') return 'Publicando uma nova versão. O launcher pode ficar indisponível por alguns minutos.';
    return 'Todos os sistemas operacionais. O launcher está funcionando normalmente.';
  }

  function rotuloServidor(s) {
    if (s === 'online') return 'ONLINE';
    if (s === 'manutencao') return 'EM MANUTENÇÃO';
    return String(s || '').toUpperCase();
  }

  function aplicar(dados) {
    if (!dados || typeof dados !== 'object') return;
    var launcher = dados.launcher || {};
    var servidor = dados.servidor || {};
    var jogadores = dados.jogadores || {};
    var manutencao = dados.manutencao || {};
    var seguranca = dados.seguranca || {};
    var links = dados.links || {};

    var status = String(launcher.status || 'estavel');
    if (!ESTADOS[status]) status = 'estavel';

    var hero = $('hero');
    if (hero) hero.className = 'hero state-' + status;
    texto('estado-geral', ESTADOS[status]);
    texto('estado-descricao', descricaoPara(status, manutencao.aviso));

    var caixaAviso = $('aviso-manutencao');
    if (caixaAviso) {
      if (manutencao.ativa && manutencao.aviso) {
        texto('aviso-texto', manutencao.aviso);
        caixaAviso.className = 'aviso';
      } else {
        texto('aviso-texto', '');
        caixaAviso.className = 'aviso oculto';
      }
    }

    texto('versao-launcher', launcher.versao);
    texto('launcher-atualizado', launcher.atualizadoEm ? ('Info atualizada em ' + formatarHoraBrasilia(launcher.atualizadoEm)) : null);
    texto('servidor-status', rotuloServidor(servidor.status));
    texto('servidor-memoria', typeof servidor.memoriaMb === 'number' ? ('Memória do processo: ' + servidor.memoriaMb + ' MB') : null);
    texto('uptime', formatarUptime(servidor.uptimeSegundos));
    texto('jogadores-online', typeof jogadores.online === 'number' ? jogadores.online : 0);
    texto('data-hora', formatarHoraBrasilia(servidor.agora));
    texto('verificado-em', 'Verificado às ' + formatarHoraBrasilia(servidor.agora) + ' (horário de Brasília)');

    if (seguranca.ultimaAuditoria) {
      var quando = Date.parse(seguranca.ultimaAuditoria);
      texto('seguranca-auditoria', isNaN(quando) ? seguranca.ultimaAuditoria : ('Auditoria: ' + formatarHoraBrasilia(new Date(quando).toISOString())));
    } else {
      texto('seguranca-auditoria', 'Sem auditoria registrada');
    }
    texto('seguranca-observacao', seguranca.observacao);

    var elDiscord = $('link-discord');
    var url = linkSeguro(links.discord);
    if (elDiscord) {
      if (url) {
        elDiscord.textContent = 'Entrar no Discord';
        elDiscord.setAttribute('href', url);
        elDiscord.setAttribute('rel', 'noopener noreferrer');
        elDiscord.setAttribute('target', '_blank');
        elDiscord.className = '';
      } else {
        elDiscord.textContent = 'Discord não configurado';
        elDiscord.removeAttribute('href');
        elDiscord.className = 'indisponivel';
      }
    }
    texto('link-site', links.site ? String(links.site) : 'Em breve');
  }

  function mostrarFalha() {
    var hero = $('hero');
    if (hero) hero.className = 'hero state-falha';
    texto('estado-geral', 'SEM CONEXÃO');
    texto('estado-descricao', 'Não foi possível atualizar o status agora. Tentando de novo em alguns segundos.');
    texto('verificado-em', 'Falha na última verificação');
  }

  function atualizar() {
    try {
      fetch('/api/status', { cache: 'no-store', headers: { Accept: 'application/json' } })
        .then(function (r) { if (!r.ok) throw new Error('http_' + r.status); return r.json(); })
        .then(function (d) {
          if (!d || d.ok === false) throw new Error('status_indisponivel');
          aplicar(d);
        })
        .catch(function () { mostrarFalha(); });
    } catch (e) {
      mostrarFalha();
    }
  }

  try { aplicar(INITIAL_STATUS); } catch (e) {}
  atualizar();
  setInterval(atualizar, REFRESH_MS);
  setInterval(function () { texto('data-hora', formatarHoraBrasilia(null)); }, 1000);
})();
</script>
</body>
</html>`;
}

/** JSON público — nunca derruba o servidor: qualquer falha vira erro tratado. */
app.get('/api/status', (_req, res) => {
  try {
    res.setHeader('Cache-Control', 'no-store');
    res.json(montarStatusPublico());
  } catch (e) {
    try {
      res.status(500).json({ ok: false, error: 'status_indisponivel' });
    } catch (_) {}
  }
});

/** Página pública de status (HTML único, sem arquivo estático e sem CDN). */
app.get('/status', (_req, res) => {
  try {
    res.setHeader('Cache-Control', 'no-store');
    res.type('html').send(renderStatusPage());
  } catch (e) {
    try {
      res.status(500).type('html').send('<!doctype html><meta charset="utf-8"><p>Status temporariamente indisponível.</p>');
    } catch (_) {}
  }
});

app.get('/api/creators', (_req, res) => {
  try {
    const m = readManifest();
    res.json({ creators: m.creators || [] });
  } catch (e) {
    res.status(500).json({ error: 'creators_failed' });
  }
});

app.post('/api/redeem', async (req, res) => {
  // F16: IP REAL (clientKey) — nunca o X-Forwarded-For cru do cliente.
  const ipR = clientKey(req);
  const usernameInicial = String((req.body && req.body.username) || '').trim().slice(0, 40);
  if (!redeemGlobalAllow()) {
    redeemAbuseNote(ipR, usernameInicial, 'global_por_minuto');
    return res.status(429).json({ ok: false, error: 'Too many redeem attempts' });
  }
  if (!rateLimit(ipR, 'redeem', 10, 60000)) {
    redeemAbuseNote(ipR, usernameInicial, 'ip_por_minuto');
    return res.status(429).json({ ok: false, error: 'Too many redeem attempts' });
  }

  try {
    if (isRateLimited(req)) {
      redeemAbuseNote(ipR, usernameInicial, 'repeticoes_por_minuto');
      return res.status(429).json({ error: 'too_many_attempts' });
    }
    const code = String(req.body?.code || '').trim().toUpperCase().slice(0, 64);
    const username = String(req.body?.username || '').trim().slice(0, 40);
  const socialToken = String((req.headers.authorization || '').replace(/^Bearer /i, '') || '').slice(0, 80);
    // F16 (camada por CONTA): o mesmo dono nao multiplica tentativas trocando de IP.
    // A identidade vem do TOKEN (nunca do body) ou do UUID quando nao ha social.
    let contaRedeem = null;
    try {
      if (socialToken && social && typeof social.findUserByToken === 'function') {
        const u = social.findUserByToken(socialToken);
        if (u && u.id) contaRedeem = 'acct:' + u.id;
      }
      if (!contaRedeem) {
        const uBruto = String(req.headers['x-reality-uuid'] || (req.body && req.body.uuid) || '').trim();
        if (/^[0-9a-fA-F-]{32,36}$/.test(uBruto)) contaRedeem = 'uuid:' + normalizeUuid(uBruto);
      }
    } catch (_) {}
    if (contaRedeem && !rateLimit(contaRedeem, 'redeem-conta', REDEEM_ACCT_MAX_PER_MIN, 60000)) {
      redeemAbuseNote(ipR, username, 'conta_por_minuto');
      return res.status(429).json({ ok: false, error: 'too_many_attempts_account' });
    }
    if (!code) return res.status(400).json({ error: 'missing_code' });
    // Identidade da conta (token social ou conta offline/uuid) — usada para creditar
    // a recompensa de moedas do código AQUI no servidor, nunca no config do jogador.
    const coinsIdentRedeem = coinsIdentity(req);
    // Lista negra: conta banida não resgata código (nem moeda, nem recompensa).
    const banRedeem = banCheckRequest(req, coinsIdentRedeem);
    if (banRedeem) return res.status(403).json(banBlockBody(banRedeem));

    const result = await withRedeemLock(async () => {
      const m = readManifest();
      const entry = (m.codes || {})[code];
      if (!entry) return { status: 404, body: { error: 'invalid_code' } };

      // Um jogador não pode resgatar o mesmo código duas vezes, mesmo quando
      // o código tem usos ilimitados. Só aplicamos a regra se houver nome.
      // SEGURANCA: com token social o resgate fica amarrado a CONTA (trocar o nick nao libera de novo).
  let contaId = null;
  try {
    if (socialToken && social && typeof social.findUserByToken === 'function') {
      const u = social.findUserByToken(socialToken);
      if (u && u.id) contaId = 'acct:' + u.id;
    }
  } catch (_) {}
  const redeemer = contaId || (username ? hashRedeemer(username) : null);
      const redeemedBy = Array.isArray(entry.redeemedBy) ? entry.redeemedBy : [];
      // ORDEM DAS CHECAGENS: identidade/duplicidade ANTES de estoque e validade.
      // A MESMA conta que já usou (mesmo num código esgotado) recebe 409
      // code_already_redeemed; OUTRA conta num código esgotado recebe 410
      // code_exhausted — antes tudo virava 410 e o jogador não entendia.
      // Vale para todo código de uso limitado; código ilimitado (usesLeft null)
      // segue idêntico ao de antes.
      if (redeemer && redeemedBy.includes(redeemer)) {
        return { status: 409, body: { error: 'code_already_redeemed' } };
      }
      // Recompensa de SELO EXCLUSIVO (ex.: beta_test) identificada AQUI, ANTES das
      // checagens de estoque/validade: o selo é amarrado à CONTA, então a MESMA
      // conta recebe 409 mesmo com o código esgotado e OUTRA conta recebe 410
      // (antes, com usesLeft 1, a mesma pessoa levava 410 e não entendia).
      const sealPedido = String(
        (entry.reward && typeof entry.reward === 'object' && entry.reward.seal) || entry.seal || ''
      ).trim().toLowerCase();
      const seloExclusivo = !!COIN_SEAL_EXCLUSIVE[sealPedido];
      // CAPA EXCLUSIVA pedida por este código (ex.: capa_beta_test): a POSSE é
      // gravada na CONTA (ownedCapes) — identificada AQUI, junto do selo, para
      // valer a mesma ordem de checagens (dup da conta antes de estoque).
      const capaPedida = /^[a-z0-9_]{3,40}$/.test(
        String((entry.reward && typeof entry.reward === 'object' && entry.reward.capeId) || entry.capeId || '').trim()
      ) ? String((entry.reward && entry.reward.capeId) || entry.capeId).trim() : null;
      // Código que ENTREGA POSSE NA CONTA (selo e/ou capa) exige identidade.
      const exigeConta = seloExclusivo || !!capaPedida;
      const contaKey = coinsIdentRedeem && coinsIdentRedeem.key ? String(coinsIdentRedeem.key) : null;
      // Chave de duplicidade da CONTA (social/id ou offline/uuid): o mesmo dono
      // não leva o selo/capa duas vezes nem trocando o nick do launcher.
      const chaveConta = exigeConta && contaKey ? 'k:' + contaKey : null;
      if (chaveConta && redeemedBy.includes(chaveConta)) {
        return { status: 409, body: { error: 'code_already_redeemed' } };
      }
      if (entry.usesLeft != null && Number(entry.usesLeft) <= 0) {
        return { status: 410, body: { error: 'code_exhausted' } };
      }
      if (entry.expiresAt && (!Number.isFinite(Date.parse(entry.expiresAt)) || Date.now() > Date.parse(entry.expiresAt))) {
        return { status: 410, body: { error: 'code_expired' } };
      }
      // Selo/capa exige CONTA: sem identidade o código nem é consumido (por isso
      // esta checagem vem DEPOIS do esgotado — código esgotado sem identidade = 410).
      if (exigeConta && !contaKey) {
        return { status: 400, body: { error: 'no_account', message: 'Entre numa conta para resgatar este codigo.' } };
      }

      if (entry.usesLeft != null) entry.usesLeft = Math.max(0, Number(entry.usesLeft) - 1);
      if (redeemer) {
        // Limita o histórico para não deixar o manifesto crescer sem controle.
        entry.redeemedBy = [...redeemedBy, redeemer].slice(-5000);
      }
      // Chave de CONTA do selo exclusivo (social/id ou offline/uuid): engorda o
      // histórico SEM duplicar e SEM mexer no que o bloco acima gravou — assim a
      // mesma conta não leva o selo duas vezes nem trocando o nick.
      if (chaveConta && !(Array.isArray(entry.redeemedBy) ? entry.redeemedBy : []).includes(chaveConta)) {
        entry.redeemedBy = [...(Array.isArray(entry.redeemedBy) ? entry.redeemedBy : []), chaveConta].slice(-5000);
      }
      if (redeemer || entry.usesLeft != null) {
        m.codes[code] = entry;
        persistManifest(m);
      }

      const source = entry.reward && typeof entry.reward === 'object' ? entry.reward : entry;
      // Selo EXCLUSIVO do código: a POSSE é gravada AQUI, na conta (ownedSeals do
      // data/coins.json) — o launcher só espelha o que o GET /api/coins devolve.
      let seloCreditado = false;
      if (seloExclusivo) {
        try {
          const g = await coinsGrantSeal(coinsIdentRedeem, sealPedido, code);
          seloCreditado = !!(g && g.granted);
        } catch (_) {}
      }
      // CAPA EXCLUSIVA do código: a POSSE é gravada na CONTA (ownedCapes do
      // data/coins.json) — SEM moeda nenhuma envolvida. O launcher só espelha o
      // que o GET /api/coins devolve (ownedCapes).
      let capaCreditada = false;
      if (capaPedida) {
        try {
          const g = await coinsGrantCape(coinsIdentRedeem, capaPedida, code);
          capaCreditada = !!(g && g.granted);
        } catch (_) {}
      }
      const premioMoedas = Math.max(0, Math.min(100000, Math.floor(Number(source.coins) || 0)));
      // Recompensa de moedas (opcional): creditada AQUI (o servidor é a fonte de
      // verdade da economia) — o launcher não soma mais nada no config local.
      let moedasCreditadas = 0;
      if (premioMoedas > 0) {
        try {
          const r = await coinsCreditRedeem(coinsIdentRedeem, premioMoedas, code);
          moedasCreditadas = (r && r.credited) || 0;
        } catch (_) {}
      }
      return {
        status: 200,
        body: {
          ok: true,
          code,
          visual: String(source.visual || '').replace(/[^a-z0-9-]/gi, '').slice(0, 40) || null,
          badge: String(source.badge || '').replace(/[^\p{L}\p{N} .-]/gu, '').slice(0, 60) || null,
          // Recompensa de capa exclusiva (opcional) — arquivo só pode referenciar algo
          // dentro de assets/custom-capes/, nunca um caminho arbitrário.
          cape: /^[a-z0-9_-]+\.png$/i.test(String(source.cape || '')) ? source.cape : null,
          role: String(source.role || '').replace(/[^\p{L}\p{N} .-]/gu, '').slice(0, 60) || null,
          displayName: String(source.displayName || '').replace(/[^\p{L}\p{N} ._-]/gu, '').slice(0, 40) || null,
          // Recompensa de moedas (opcional): valor do catálogo do código; o crédito
          // de verdade foi feito acima no servidor (coinsCredited = quanto entrou).
          coins: premioMoedas,
          coinsCredited: moedasCreditadas,
          // Selo exclusivo do código (id) + se a posse entrou AGORA na conta. Quem
          // confirma a posse é o GET /api/coins (ownedSeals) — nunca o cliente.
          seal: seloExclusivo ? sealPedido : null,
          sealGranted: seloCreditado,
          // CAPA EXCLUSIVA do código (id do catálogo do launcher) + se a posse
          // entrou AGORA na conta. Quem confirma é o GET /api/coins (ownedCapes).
          capeId: capaPedida,
          capeGranted: capaCreditada,
          username: username || null,
          redeemedAt: Date.now()
        }
      };
    });
    res.status(result.status).json(result.body);
  } catch (e) {
    res.status(500).json({ error: 'redeem_failed' });
  }
});

// ---------- Admin (só com token) ----------

app.get('/api/admin/manifest', requireAdmin, (_req, res) => {
  res.json(readManifest());
});

/** Substitui o manifesto inteiro (ou merge parcial) */
app.post('/api/admin/manifest', requireAdmin, (req, res) => {
  try {
    const current = readManifest();
    const body = req.body || {};
    const next = {
      ...current,
      ...body,
      launcher: { ...(current.launcher || {}), ...(body.launcher || {}) },
      discord: { ...(current.discord || {}), ...(body.discord || {}) },
      features: { ...(current.features || {}), ...(body.features || {}) },
      announcement: { ...(current.announcement || {}), ...(body.announcement || {}) },
      creators: body.creators != null ? body.creators : current.creators,
      topDonors: body.topDonors != null ? body.topDonors : current.topDonors,
      codes: body.codes != null ? body.codes : current.codes
    };
    res.json(writeManifest(next));
  } catch (e) {
    res.status(500).json({ error: 'admin_save_failed', detail: e.message });
  }
});

app.post('/api/admin/creators', requireAdmin, (req, res) => {
  try {
    const m = readManifest();
    m.creators = Array.isArray(req.body?.creators) ? req.body.creators : m.creators;
    res.json(writeManifest(m));
  } catch (e) {
    res.status(500).json({ error: 'admin_creators_failed' });
  }
});

app.post('/api/admin/codes', requireAdmin, (req, res) => {
  try {
    const m = readManifest();
    m.codes = req.body?.codes && typeof req.body.codes === 'object' ? req.body.codes : m.codes;
    res.json(writeManifest(m));
  } catch (e) {
    res.status(500).json({ error: 'admin_codes_failed' });
  }
});

app.post('/api/admin/announcement', requireAdmin, (req, res) => {
  try {
    const m = readManifest();
    m.announcement = { ...(m.announcement || {}), ...(req.body || {}) };
    res.json(writeManifest(m));
  } catch (e) {
    res.status(500).json({ error: 'admin_announcement_failed' });
  }
});

app.post('/api/admin/launcher', requireAdmin, (req, res) => {
  try {
    const m = readManifest();
    m.launcher = { ...(m.launcher || {}), ...(req.body || {}) };
    res.json(writeManifest(m));
  } catch (e) {
    res.status(500).json({ error: 'admin_launcher_failed' });
  }
});

// ---------- Admin: lista negra (bans) ----------
// Adiciona/atualiza (POST) e remove (DELETE) nicks/uuids SEM deploy: o launcher
// pega a lista nova em GET /api/bans (cache curto) e bloqueia o launch.
app.get('/api/admin/bans', requireAdmin, (_req, res) => {
  try {
    const dados = readBans(true);
    res.json({ ok: true, version: dados.version, updatedAt: dados.updatedAt, count: dados.bans.length, bans: dados.bans.map((b) => Object.assign(banPublicEntry(b), { hwid2: b.hwid2 || '', comps: Array.isArray(b.comps) ? b.comps : [] })) });
  } catch (_) {
    try { res.status(500).json({ ok: false, error: 'bans_read_failed' }); } catch (_2) {}
  }
});

app.post('/api/admin/bans', requireAdmin, (req, res) => {
  try {
    const body = req.body || {};
    const entradas = Array.isArray(body.bans) ? body.bans : [body];
    const dados = readBans(true);
    const lista = dados.bans.slice();
    let adicionados = 0;
    let atualizados = 0;
    const comHwid = [];
    for (const bruto of entradas.slice(0, 500)) {
      const limpo = bansSanitizeEntry(bruto);
      if (!limpo) continue;
      // Enriquecimento: ban por hwid aproveita o hwid-map para guardar o CONJUNTO
      // de sinais (hwid2/comps) — sem isso o ban so vale pelo hash v1 exato.
      if (limpo.hwid && !(limpo.comps && limpo.comps.length)) {
        try {
          const e = hwidMapLoad()[limpo.hwid];
          if (e && typeof e === 'object') {
            if (!limpo.hwid2 && /^[a-f0-9]{64}$/.test(String(e.hwid2 || ''))) limpo.hwid2 = String(e.hwid2);
            if (Array.isArray(e.comps) && e.comps.length) limpo.comps = e.comps.filter((c) => DEVICE_COMP_RE.test(String(c))).slice(0, DEVICE_V2_MAX_COMPS);
          }
        } catch (_) {}
      }
      const i = lista.findIndex((b) => (
        (limpo.username && b.username && b.username.toLowerCase() === limpo.username.toLowerCase()) ||
        (limpo.uuid && b.uuid && bansUuidEq(b.uuid, limpo.uuid)) ||
        (limpo.hwid && b.hwid && b.hwid === limpo.hwid) ||
        (limpo.hwid2 && b.hwid2 && b.hwid2 === limpo.hwid2)
      ));
      if (i >= 0) {
        const fundido = { ...lista[i], ...limpo };
        fundido.hwid2 = limpo.hwid2 || lista[i].hwid2 || '';
        fundido.comps = (limpo.comps && limpo.comps.length) ? limpo.comps : (Array.isArray(lista[i].comps) ? lista[i].comps : []);
        lista[i] = fundido;
        atualizados += 1;
      } else {
        lista.push(limpo);
        adicionados += 1;
      }
      if (limpo.hwid) comHwid.push(limpo);
    }
    const proximo = writeBansFile({
      version: Math.max(1, Math.floor(Number(dados.version) || 1)) + 1,
      updatedAt: new Date().toISOString(),
      bans: lista.slice(0, BANS_MAX_ENTRIES)
    });
    // Aviso no webhook do Guard: ban por HWID aplicado (o dono/equipe acompanha).
    try {
      if (comHwid.length) {
        const url = guardWebhookUrl();
        if (url) {
          guardWebhookPost(url, {
            username: 'Reality Guard',
            embeds: [{
              title: '⛔ Ban por HWID (placa-mae) aplicado',
              color: 0xB00020,
              fields: comHwid.slice(0, 15).map((b) => ({
                name: (b.username || b.uuid || 'hwid'),
                value: '`' + String(b.hwid).slice(0, 24) + '…` — ' + String(b.reason || '').slice(0, 120),
                inline: false
              })),
              footer: { text: 'data/bans.json — vale mesmo com nick/conta novos e .reality apagado' }
            }]
          }).catch(() => {});
        }
      }
    } catch (_) {}
    res.json({ ok: true, added: adicionados, updated: atualizados, count: proximo.bans.length, bans: proximo.bans.map(banPublicEntry) });
  } catch (_) {
    try { res.status(500).json({ ok: false, error: 'bans_save_failed' }); } catch (_2) {}
  }
});

app.delete('/api/admin/bans', requireAdmin, (req, res) => {
  try {
    const body = req.body || {};
    const username = String(body.username || req.query.username || '').trim().toLowerCase();
    const uuid = String(body.uuid || req.query.uuid || '').trim();
    const hwid = String(body.hwid || req.query.hwid || '').trim().toLowerCase();
    if (!username && !uuid && !hwid) return res.status(400).json({ ok: false, error: 'missing_username_uuid_or_hwid' });
    const dados = readBans(true);
    const antes = dados.bans.length;
    const lista = dados.bans.filter((b) => {
      if (username && b.username && b.username.toLowerCase() === username) return false;
      if (uuid && b.uuid && bansUuidEq(b.uuid, uuid)) return false;
      if (hwid && b.hwid && b.hwid === hwid) return false;
      if (hwid && b.hwid2 && b.hwid2 === hwid) return false;
      return true;
    });
    const proximo = writeBansFile({
      version: Math.max(1, Math.floor(Number(dados.version) || 1)) + 1,
      updatedAt: new Date().toISOString(),
      bans: lista
    });
    res.json({ ok: true, removed: antes - proximo.bans.length, count: proximo.bans.length, bans: proximo.bans.map(banPublicEntry) });
  } catch (_) {
    try { res.status(500).json({ ok: false, error: 'bans_delete_failed' }); } catch (_2) {}
  }
});

// ---------- Social (amigos, pedidos, chat, presença) ----------
const { createSocial } = require('./social');
const social = createSocial(DATA_DIR);
// Lista negra: conta banida não abre sessão social (nem derruba as rotas dos
// outros). O launcher também bloqueia o próprio launch dessa conta.
app.use('/api/social', (req, res, next) => {
  try {
    const body = req.body || {};
    const apresentado = String(body.token || '') || String(req.headers.authorization || '').replace(/^Bearer\s+/i, '');
    let alvo = { username: body.username || body.name || '', uuid: body.uuid || '', key: '' };
    if (apresentado) {
      let dono = null;
      try { dono = social.findUserByToken(apresentado); } catch (_) { dono = null; }
      if (dono) alvo = { username: dono.username || '', uuid: dono.uuid || '', key: '' };
    }
    const banido = banMatch(alvo);
    if (banido) return res.status(403).json(banBlockBody(banido));
  } catch (_) {}
  next();
});
social.mount(app);


// ---------- Reality Guard reports (donos) ----------
const guardReports = [];
const GUARD_ADMIN_KEY = process.env.GUARD_ADMIN_KEY || process.env.ADMIN_KEY || '';
const GUARD_KEY_IS_DEFAULT = !GUARD_ADMIN_KEY;
if (GUARD_KEY_IS_DEFAULT) console.warn('[guard] GUARD_ADMIN_KEY nao definida - leitura de relatorios desabilitada');
const MAX_GUARD_REPORTS = 500;

// ---------- Webhook do Discord (Guard) ----------
// Config: ENV GUARD_WEBHOOK_URL (preferida) com fallback opcional em
// <data>/guard-webhook.json ({ "url": "https://discord.com/api/webhooks/..." }).
// SEGURANCA: a URL NUNCA vai inteira para o log (só o host). Uma falha de webhook
// NUNCA quebra o report: o envio é fire-and-forget, com timeout e try/catch.
// Anti-spam/anti-loop: no máximo 1 mensagem por report, dedupe por
// conta+motivo+hits (janela GUARD_WEBHOOK_DEDUPE_MS, padrão 60s) e teto de
// GUARD_WEBHOOK_MAX_PER_MIN envios por minuto. Report repetido continua sendo
// gravado (ok:true) — só não vira mensagem de novo.
const GUARD_WEBHOOK_FILE = path.join(DATA_DIR, 'guard-webhook.json');
const GUARD_WEBHOOK_TIMEOUT_MS = 8000;
const GUARD_WEBHOOK_DEDUPE_MS = Math.max(5000, Math.floor(Number(process.env.GUARD_WEBHOOK_DEDUPE_MS) || 60000));
const GUARD_WEBHOOK_MAX_PER_MIN = Math.max(1, Math.floor(Number(process.env.GUARD_WEBHOOK_MAX_PER_MIN) || 10));
const GUARD_REPORT_MAX_PER_MIN = Math.max(1, Math.floor(Number(process.env.GUARD_REPORT_MAX_PER_MIN) || 30));
let guardWebhookFileCache = { at: 0, url: '' };
const guardWebhookDedupe = new Map(); // chave -> último envio (ms)
let guardWebhookJanela = { start: 0, count: 0 };

/** F17: o backend so faz UMA chamada de saida (webhook do Guard). Nunca para
 *  loopback/rede privada — se alguem escrever data/guard-webhook.json, nao
 *  transforma o backend num scanner da rede interna do VPS. */
function guardWebhookAllowed(url) {
  try {
    const u = new URL(url);
    if (u.protocol !== 'https:' && u.protocol !== 'http:') return false;
    return !hostguard.isPrivateHost(u.hostname);
  } catch (_) {
    return false;
  }
}

function guardWebhookUrl() {
  const env = String(process.env.GUARD_WEBHOOK_URL || '').trim();
  if (/^https?:\/\//i.test(env) && guardWebhookAllowed(env)) return env;
  const agora = Date.now();
  if (agora - guardWebhookFileCache.at > 60000) {
    let url = '';
    try {
      if (fs.existsSync(GUARD_WEBHOOK_FILE)) {
        const bruto = JSON.parse(fs.readFileSync(GUARD_WEBHOOK_FILE, 'utf-8'));
        url = String((bruto && bruto.url) || '').trim();
      }
    } catch (_) { url = ''; }
    guardWebhookFileCache = { at: agora, url: guardWebhookAllowed(url) ? url : '' };
  }
  return guardWebhookFileCache.url;
}

function guardWebhookHost(url) {
  try { return new URL(url).host || '(host desconhecido)'; } catch (_) { return '(url invalida)'; }
}

/** Horário de Brasília (America/Sao_Paulo) — cai pro ISO se o runtime não tiver tz. */
function guardBrasiliaTime(ms) {
  try {
    return new Intl.DateTimeFormat('pt-BR', {
      timeZone: 'America/Sao_Paulo',
      day: '2-digit', month: '2-digit', year: 'numeric',
      hour: '2-digit', minute: '2-digit', second: '2-digit'
    }).format(new Date(ms || Date.now()));
  } catch (_) {
    try { return new Date(ms || Date.now()).toISOString(); } catch (_2) { return '(horario indisponivel)'; }
  }
}

/** Converte os hits (JSON string ou objeto) em linhas legíveis pro embed. */
function guardHitLines(itens, kindFiltro) {
  const arr = Array.isArray(itens) ? itens : [];
  const linhas = [];
  for (const bruto of arr) {
    let h = bruto;
    if (typeof bruto === 'string') { try { h = JSON.parse(bruto); } catch (_) { h = null; } }
    if (!h || typeof h !== 'object') continue;
    const kind = String(h.kind || '');
    if (kindFiltro === 'blocked' && kind !== 'blocked') continue;
    if (kindFiltro === 'warning' && kind === 'blocked') continue;
    const file = String(h.file || h.name || '?').replace(/[\r\n]+/g, ' ').slice(0, 100);
    const reason = String(h.reason || 'sem detalhe').replace(/[\r\n]+/g, ' ').slice(0, 150);
    linhas.push('• `' + file + '` — ' + reason);
  }
  return linhas;
}

function guardListaFormatada(linhas, limite) {
  const corte = linhas.slice(0, limite);
  if (linhas.length > limite) corte.push('… +' + (linhas.length - limite) + ' item(ns)');
  return corte.join('\n').slice(0, 1000) || '—';
}

/** Monta a mensagem (embed) com nick, conta/uuid, motivo, bloqueios/avisos, versão e hora. */
function guardWebhookPayload(report) {
  const bloqueados = guardHitLines(report.hits, 'blocked');
  const avisos = guardHitLines(report.hits, 'warning');
  const conta = String(report.account || report.uuid || 'offline').slice(0, 80);
  return {
    username: 'Reality Guard',
    embeds: [{
      title: '🛡️ Reality Guard — ' + (bloqueados.length ? 'bloqueio detectado' : 'aviso'),
      color: bloqueados.length ? 0xE74C3C : 0xF1C40F,
      fields: [
        { name: 'Jogador', value: '`' + (report.username || 'unknown') + '`', inline: true },
        { name: 'Conta / UUID', value: '`' + conta + '`', inline: true },
        { name: 'Motivo', value: String(report.reason || 'guard').slice(0, 200), inline: true },
        { name: 'Bloqueado (' + bloqueados.length + ')', value: guardListaFormatada(bloqueados, 10), inline: false },
        { name: 'Avisos (' + avisos.length + ')', value: guardListaFormatada(avisos, 10), inline: false },
        { name: 'Launcher', value: '`' + String(report.launcherVersion || report.version || '?').slice(0, 40) + '`', inline: true },
        { name: 'Horário (Brasília)', value: guardBrasiliaTime(report.at), inline: true }
      ],
      footer: { text: 'report ' + report.id }
    }]
  };
}

function guardWebhookPost(url, payload) {
  return new Promise((resolve) => {
    try {
      const lib = /^https:/i.test(url) ? require('https') : require('http');
      const u = new URL(url);
      const corpo = Buffer.from(JSON.stringify(payload), 'utf-8');
      const req = lib.request({
        protocol: u.protocol,
        hostname: u.hostname,
        port: u.port || undefined,
        path: u.pathname + u.search,
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'Content-Length': corpo.length }
      }, (resp) => {
        try { resp.resume(); } catch (_) {}
        resolve({ status: resp.statusCode || 0 });
      });
      req.setTimeout(GUARD_WEBHOOK_TIMEOUT_MS, () => { try { req.destroy(new Error('webhook_timeout')); } catch (_) {} });
      req.on('error', () => resolve({ status: -1 }));
      req.write(corpo);
      req.end();
    } catch (_) {
      resolve({ status: -1 });
    }
  });
}

/**
 * Decide (síncrono) se ESTE report vira mensagem e dispara UM envio
 * (fire-and-forget). Retorna 'sent' | 'deduped' | 'throttled' | 'disabled'.
 */
function guardWebhookDispatch(report) {
  let url = '';
  try { url = guardWebhookUrl(); } catch (_) { url = ''; }
  if (!url) return 'disabled';
  let chave = report.id;
  try {
    chave = [
      String(report.username || ''),
      String(report.uuid || ''),
      String(report.reason || ''),
      require('crypto').createHash('sha1').update(JSON.stringify(report.hits || [])).digest('hex').slice(0, 12)
    ].join('|');
  } catch (_) { /* usa o id do report como chave */ }
  const agora = Date.now();
  const ultimo = guardWebhookDedupe.get(chave) || 0;
  if (agora - ultimo < GUARD_WEBHOOK_DEDUPE_MS) return 'deduped';
  if (agora - guardWebhookJanela.start > 60000) guardWebhookJanela = { start: agora, count: 0 };
  if (guardWebhookJanela.count >= GUARD_WEBHOOK_MAX_PER_MIN) return 'throttled';
  guardWebhookDedupe.set(chave, agora);
  guardWebhookJanela.count += 1;
  if (guardWebhookDedupe.size > 2000) {
    for (const [k, t] of guardWebhookDedupe) {
      if (agora - t > GUARD_WEBHOOK_DEDUPE_MS) guardWebhookDedupe.delete(k);
    }
  }
  const host = guardWebhookHost(url); // log só com o host — nunca a URL inteira
  const payload = guardWebhookPayload(report);
  guardWebhookPost(url, payload).then((r) => {
    if (r && r.status >= 200 && r.status < 300) console.log('[guard] webhook enviado (' + host + ') report ' + report.id);
    else console.log('[guard] webhook falhou (' + host + ') status=' + (r && r.status) + ' report ' + report.id);
  }).catch(() => {});
  return 'sent';
}

app.post('/api/guard/report', (req, res) => {
  try {
    // Limite por IP (clientKey — X-Forwarded-For é forjável) pro endpoint de report.
    if (!rateLimit(clientKey(req), 'guard-report', GUARD_REPORT_MAX_PER_MIN, 60000)) {
      return res.status(429).json({ ok: false, error: 'too_many_reports' });
    }
    const body = req.body || {};
    const report = {
      id: 'g_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 7),
      at: Date.now(),
      username: String(body.username || body.name || 'unknown').replace(/[\r\n\t]/g, ' ').slice(0, 32),
      uuid: String(body.uuid || '').slice(0, 64),
      account: String(body.account || '').replace(/[\r\n\t]/g, ' ').slice(0, 80),
      hits: (Array.isArray(body.hits) ? body.hits.slice(0, 40) : []).map((h) => {
        try { return JSON.stringify(h).slice(0, 400); } catch (_) { return 'invalid_hit'; }
      }),
      version: String(body.version || '').slice(0, 32),
      launcherVersion: String(body.launcherVersion || '').slice(0, 32),
      reason: String(body.reason || 'guard').slice(0, 64)
    };
    guardReports.unshift(report);
    if (guardReports.length > MAX_GUARD_REPORTS) guardReports.length = MAX_GUARD_REPORTS;
    console.log('[guard]', report.username, report.hits.length, 'hit(s)');
    // Webhook: no máximo UMA mensagem por report (dedupe/teto anti-loop), sempre
    // fire-and-forget — qualquer falha aqui NUNCA muda a resposta do report.
    let webhook = 'disabled';
    try { webhook = guardWebhookDispatch(report); } catch (_) { webhook = 'error'; }
    res.json({ ok: true, id: report.id, webhook });
  } catch (e) {
    res.status(500).json({ ok: false });
  }
});

app.get('/api/guard/reports', (req, res) => {
  if (GUARD_KEY_IS_DEFAULT) {
    return res.status(503).json({ ok: false, error: 'guard_admin_disabled_no_key' });
  }
  const key = String(req.query.key || req.headers['x-admin-key'] || '');
  if (key !== GUARD_ADMIN_KEY) {
    return res.status(401).json({ ok: false, error: 'unauthorized' });
  }
  const limit = Math.min(100, Math.max(1, parseInt(req.query.limit || '50', 10) || 50));
  res.json({ ok: true, total: guardReports.length, reports: guardReports.slice(0, limit) });
});


// ---------- 1.6.76 — Revisões do Guard ("não é cheat — enviar para revisão") ----------
// O jogador manda o ARQUIVO bloqueado/avisado (nome + sha256 + motivo) direto
// pela UI do launcher; aqui guardamos (pro dono revisar) e avisamos no webhook.
// Um pedido de revisão NUNCA muda o veredito do Guard — só entra na fila humana.
const GUARD_REVIEWS_FILE = path.join(DATA_DIR, 'guard-reviews.json');
const MAX_GUARD_REVIEWS = 300;
const GUARD_REVIEW_MAX_PER_MIN = Math.max(1, Math.floor(Number(process.env.GUARD_REVIEW_MAX_PER_MIN) || 12));
let guardReviews = null;

function guardReviewsLoad() {
  if (guardReviews) return guardReviews;
  guardReviews = [];
  try {
    if (fs.existsSync(GUARD_REVIEWS_FILE)) {
      const b = JSON.parse(fs.readFileSync(GUARD_REVIEWS_FILE, 'utf-8'));
      if (Array.isArray(b)) guardReviews = b.slice(0, MAX_GUARD_REVIEWS);
    }
  } catch (_) { guardReviews = []; }
  return guardReviews;
}

function guardReviewsSave() {
  try {
    const tmp = GUARD_REVIEWS_FILE + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(guardReviewsLoad().slice(0, MAX_GUARD_REVIEWS), null, 2), 'utf-8');
    fs.renameSync(tmp, GUARD_REVIEWS_FILE);
  } catch (_) {}
}

function guardReviewWebhookSend(review) {
  let url = '';
  try { url = guardWebhookUrl(); } catch (_) { url = ''; }
  if (!url) return 'disabled';
  const payload = {
    username: 'Reality Guard',
    embeds: [{
      title: '📩 Revisão de mod enviada por jogador',
      color: 0x3498DB,
      fields: [
        { name: 'Arquivo', value: '`' + String(review.file || '?').slice(0, 100) + '`', inline: true },
        { name: 'Jogador', value: '`' + String(review.username || 'unknown').slice(0, 32) + '`', inline: true },
        { name: 'Motivo do Guard', value: String(review.reason || '—').slice(0, 200), inline: false },
        { name: 'Detalhe', value: String(review.detalhe || '—').slice(0, 240), inline: false },
        { name: 'sha256', value: '`' + String(review.sha256 || 'indisponível').slice(0, 64) + '`', inline: false },
        { name: 'Launcher', value: '`' + String(review.launcherVersion || '?').slice(0, 40) + '`', inline: true },
        { name: 'Horário (Brasília)', value: guardBrasiliaTime(review.at), inline: true }
      ],
      footer: { text: 'review ' + review.id }
    }]
  };
  const host = guardWebhookHost(url);
  guardWebhookPost(url, payload).then((r) => {
    if (r && r.status >= 200 && r.status < 300) console.log('[guard] webhook revisão enviado (' + host + ') ' + review.id);
    else console.log('[guard] webhook revisão falhou (' + host + ') status=' + (r && r.status));
  }).catch(() => {});
  return 'sent';
}

app.post('/api/guard/review', (req, res) => {
  try {
    if (!rateLimit(clientKey(req), 'guard-review', GUARD_REVIEW_MAX_PER_MIN, 60000)) {
      return res.status(429).json({ ok: false, error: 'too_many_reviews' });
    }
    const body = req.body || {};
    const file = String(body.file || '').replace(/[\r\n\t]/g, ' ').trim().slice(0, 120);
    if (!file) return res.status(400).json({ ok: false, error: 'missing_file' });
    const sha = String(body.sha256 || '').toLowerCase();
    const review = {
      id: 'r_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 7),
      at: Date.now(),
      file,
      sha256: /^[0-9a-f]{64}$/.test(sha) ? sha : null,
      reason: String(body.reason || '').replace(/[\r\n\t]/g, ' ').slice(0, 120),
      detalhe: String(body.detalhe || '').replace(/[\r\n\t]/g, ' ').slice(0, 240),
      kind: String(body.kind || 'blocked').slice(0, 20),
      version: String(body.version || '').slice(0, 32),
      launcherVersion: String(body.launcherVersion || '').slice(0, 32),
      username: String(body.username || body.name || 'unknown').replace(/[\r\n\t]/g, ' ').slice(0, 32),
      uuid: String(body.uuid || '').slice(0, 64)
    };
    const lista = guardReviewsLoad();
    lista.unshift(review);
    if (lista.length > MAX_GUARD_REVIEWS) lista.length = MAX_GUARD_REVIEWS;
    guardReviewsSave();
    console.log('[guard] revisão', review.file, 'de', review.username);
    let webhook = 'disabled';
    try { webhook = guardReviewWebhookSend(review); } catch (_) { webhook = 'error'; }
    res.json({ ok: true, id: review.id, webhook });
  } catch (e) {
    res.status(500).json({ ok: false });
  }
});

app.get('/api/guard/reviews', (req, res) => {
  // Aceita a GUARD_ADMIN_KEY OU o token admin rotacionado (ADMIN_TOKEN) — o dono
  // já tem esse token; sem NENHUM dos dois, leitura fica desabilitada (503).
  const adminToken = String(process.env.ADMIN_TOKEN || '');
  const aceitos = [GUARD_ADMIN_KEY, adminToken].filter(Boolean);
  if (!aceitos.length) {
    return res.status(503).json({ ok: false, error: 'guard_admin_disabled_no_key' });
  }
  const key = String(req.query.key || req.headers['x-admin-key'] || '');
  if (!aceitos.includes(key)) {
    return res.status(401).json({ ok: false, error: 'unauthorized' });
  }
  const limit = Math.min(100, Math.max(1, parseInt(req.query.limit || '50', 10) || 50));
  const lista = guardReviewsLoad();
  res.json({ ok: true, total: lista.length, reviews: lista.slice(0, limit) });
});


// ---------- Mapa HWID -> contas (aprendido do X-Reality-Device pos-fix) ----------
// Quando o launcher novo (com HWID de hardware) aparecer, CADA contato registra
// <hwid> -> { names, uuids, firstSeen, lastSeen } em <data>/hwid-map.json. Serve
// pro dono: achar o HWID de um trapaceiro que voltou (GET /api/admin/hwid-map?uuid=
// ou ?name=) e bani-lo por hardware (POST /api/admin/bans { hwid, reason }).
// Só aceita hash sha256 (64 hex) — chaves antigas aleatórias ficam de fora.
const HWID_MAP_FILE = path.join(DATA_DIR, 'hwid-map.json');
const HWID_MAP_MAX = 5000;
const HWID_MAP_HISTORY = 8;
let hwidMapMem = null;      // cache em memoria (flush a cada 30s)
let hwidMapDirty = false;

function hwidMapLoad() {
  if (hwidMapMem) return hwidMapMem;
  try {
    if (fs.existsSync(HWID_MAP_FILE)) {
      const b = JSON.parse(fs.readFileSync(HWID_MAP_FILE, 'utf-8'));
      if (b && typeof b === 'object' && !Array.isArray(b)) { hwidMapMem = b; return hwidMapMem; }
    }
  } catch (_) {}
  hwidMapMem = {};
  return hwidMapMem;
}

function hwidMapFlush() {
  if (!hwidMapDirty || !hwidMapMem) return;
  try {
    const tempFile = HWID_MAP_FILE + '.tmp';
    fs.writeFileSync(tempFile, JSON.stringify(hwidMapMem, null, 2), 'utf-8');
    fs.renameSync(tempFile, HWID_MAP_FILE);
    hwidMapDirty = false;
  } catch (_) {}
}
setInterval(hwidMapFlush, 30000).unref();

// ---------- Anomalias de device (evasao por hardware) ----------
// - Muitas CONTAS no mesmo HWID em 24h => anomalia + webhook (auto-ban OPCIONAL).
// - Muitos HWIDs distintos no mesmo IP no mesmo dia => anomalia + webhook.
// Registro: <data>/device-anomalies.json (capped). Auto-ban desligado por padrao
// (HWID_AUTOBAN_MIN_ACCOUNTS=0) — ligue com cautela (PC compartilhado em casa).
const DEVICE_ANOMALY_FILE = path.join(DATA_DIR, 'device-anomalies.json');
const DEVICE_ANOMALY_MAX = 500;
const DEVICE_ACCT_WINDOW_MS = Math.max(60 * 60 * 1000, Math.floor(Number(process.env.HWID_ACCT_WINDOW_MS) || 24 * 60 * 60 * 1000));
// 05/10: 5 -> 8. Familia/PC compartilhado com 3-4 contas é normal e estava gerando
// aviso; 8+ contas num dia continua sendo o sinal bom de evasão.
const DEVICE_ACCT_ANOMALY_MIN = Math.max(2, Math.floor(Number(process.env.HWID_ACCT_ANOMALY_MIN) || 8));
const DEVICE_AUTOBAN_MIN = Math.max(0, Math.floor(Number(process.env.HWID_AUTOBAN_MIN_ACCOUNTS) || 0));
const DEVICE_ANOM_DEDUPE_MS = 6 * 60 * 60 * 1000;
// 05/10: 25 -> 75 e aviso 1x por dia por IP. No Brasil muito provedor usa CGNAT:
// centenas de jogadores legítimos dividem o mesmo IP e o aviso de 25 virava spam
// de falso positivo. O REGISTRO continua no arquivo; o webhook é que não repete.
const IP_DEVICE_ANOMALY_MIN = Math.max(3, Math.floor(Number(process.env.HWID_IP_ANOMALY_MIN) || 75));
const IP_ANOM_DEDUPE_MS = 24 * 60 * 60 * 1000;
const deviceAnomDedupe = new Map(); // hwid -> ultimo aviso (ms)
let ipDevicesDia = { dia: '', porIp: new Map() }; // ip -> Set(hwid)
const ipAnomDedupe = new Map();     // ip|dia -> ultimo aviso (ms)

function deviceAnomalyAppend(registro) {
  try {
    fs.mkdirSync(DATA_DIR, { recursive: true });
    let lista = [];
    try {
      if (fs.existsSync(DEVICE_ANOMALY_FILE)) {
        const b = JSON.parse(fs.readFileSync(DEVICE_ANOMALY_FILE, 'utf-8'));
        if (Array.isArray(b)) lista = b;
      }
    } catch (_) { lista = []; }
    lista.unshift(registro);
    const tempFile = DEVICE_ANOMALY_FILE + '.tmp';
    fs.writeFileSync(tempFile, JSON.stringify(lista.slice(0, DEVICE_ANOMALY_MAX), null, 2), 'utf-8');
    fs.renameSync(tempFile, DEVICE_ANOMALY_FILE);
    return true;
  } catch (_) { return false; }
}

function deviceAnomalyNotify(titulo, campos, rodape) {
  try {
    const url = guardWebhookUrl();
    if (!url) return;
    guardWebhookPost(url, {
      username: 'Reality Guard',
      embeds: [{
        title: titulo,
        color: 0xE67E22,
        fields: campos.slice(0, 8),
        footer: { text: String(rodape || 'device-anomalies').slice(0, 180) }
      }]
    }).catch(() => {});
  } catch (_) {}
}

/** Auto-ban OPCIONAL do device (ligado por HWID_AUTOBAN_MIN_ACCOUNTS>0). */
function deviceAutoBan(hwid, e, contas) {
  try {
    const bans = readBans(true);
    if (bans.bans.some((b) => b.hwid === hwid)) return false;
    const limpo = bansSanitizeEntry({
      hwid,
      hwid2: String((e && e.hwid2) || ''),
      comps: Array.isArray(e && e.comps) ? e.comps : [],
      reason: 'auto: ' + contas + ' contas no mesmo hardware (possivel evasao)',
      at: Date.now()
    });
    if (!limpo) return false;
    const lista = bans.bans.concat([limpo]).slice(0, BANS_MAX_ENTRIES);
    writeBansFile({
      version: Math.max(1, Math.floor(Number(bans.version) || 1)) + 1,
      updatedAt: new Date().toISOString(),
      bans: lista
    });
    deviceAnomalyNotify('⛔ AUTO-BAN por hardware (muitas contas)', [
      { name: 'Contas/24h', value: String(contas), inline: true },
      { name: 'HWID', value: '`' + String(hwid).slice(0, 24) + '…`', inline: true },
      { name: 'Motivo', value: 'auto: ' + contas + ' contas no mesmo hardware', inline: false }
    ], 'HWID_AUTOBAN_MIN_ACCOUNTS=' + DEVICE_AUTOBAN_MIN + ' (data/bans.json)');
    return true;
  } catch (_) { return false; }
}

function deviceCheckAnomaly(hwid, e, req) {
  try {
    const agora = Date.now();
    const ip = String(clientKey(req) || '').slice(0, 64);
    // 1) muitas contas no mesmo hwid
    const janela = agora - DEVICE_ACCT_WINDOW_MS;
    let contas = 0;
    try {
      for (const info of Object.values(e.accts || {})) {
        if (info && (Number(info.at) || 0) >= janela) contas += 1;
      }
    } catch (_) {}
    e.acctsJanela = contas;
    if (contas >= DEVICE_ACCT_ANOMALY_MIN) {
      const auto = DEVICE_AUTOBAN_MIN > 0 && contas >= DEVICE_AUTOBAN_MIN;
      const ultimo = deviceAnomDedupe.get(hwid) || 0;
      if (agora - ultimo >= DEVICE_ANOM_DEDUPE_MS) {
        deviceAnomDedupe.set(hwid, agora);
        if (deviceAnomDedupe.size > 1000) {
          for (const [k, t] of deviceAnomDedupe) { if (agora - t > DEVICE_ANOM_DEDUPE_MS) deviceAnomDedupe.delete(k); }
        }
        deviceAnomalyAppend({
          at: agora,
          kind: 'device_multi_account',
          hwid,
          hwid2: String(e.hwid2 || ''),
          contas,
          names: (Array.isArray(e.names) ? e.names : []).slice(-8),
          uuids: (Array.isArray(e.uuids) ? e.uuids : []).slice(-8),
          ip,
          signed: !!e.signedAt,
          autoban: auto
        });
        deviceAnomalyNotify('🧩 MESMO HARDWARE com muitas contas', [
          { name: 'Contas na janela', value: String(contas), inline: true },
          { name: 'HWID', value: '`' + hwid.slice(0, 24) + '…`', inline: true },
          { name: 'Assinado', value: (e.signedAt ? 'sim' : 'nao'), inline: true },
          { name: 'Nicks', value: '`' + ((Array.isArray(e.names) ? e.names.slice(-8).join('`, `') : '') || '-').slice(0, 300) + '`', inline: false },
          { name: 'UUIDs', value: '`' + ((Array.isArray(e.uuids) ? e.uuids.slice(-6).join('`, `') : '') || '-').slice(0, 300) + '`', inline: false }
        ], 'hwid-map — data/device-anomalies.json (janela ' + Math.round(DEVICE_ACCT_WINDOW_MS / 3600000) + 'h)');
      }
      if (auto) deviceAutoBan(hwid, e, contas);
    }
    // 2) muitos hwids no mesmo IP no dia (rede compartilhada / raide de contas)
    try {
      const dia = new Date(agora).toISOString().slice(0, 10);
      if (ipDevicesDia.dia !== dia) ipDevicesDia = { dia, porIp: new Map() };
      if (ip) {
        let set = ipDevicesDia.porIp.get(ip);
        if (!set) { set = new Set(); ipDevicesDia.porIp.set(ip, set); }
        set.add(hwid);
        if (set.size >= IP_DEVICE_ANOMALY_MIN) {
          const chave = ip + '|' + dia;
          if (agora - (ipAnomDedupe.get(chave) || 0) >= IP_ANOM_DEDUPE_MS) {
            ipAnomDedupe.set(chave, agora);
            if (ipAnomDedupe.size > 2000) {
              for (const [k, t] of ipAnomDedupe) { if (agora - t > IP_ANOM_DEDUPE_MS) ipAnomDedupe.delete(k); }
            }
            deviceAnomalyAppend({ at: agora, kind: 'ip_multi_device', ip, hwids: set.size });
            deviceAnomalyNotify('🌐 Muitos devices no mesmo IP (hoje)', [
              { name: 'HWIDs hoje', value: String(set.size), inline: true },
              { name: 'IP', value: '`' + ip.slice(0, 48) + '`', inline: true }
            ], 'observacao (nada e banido por IP; CGNAT/rede compartilhada infla). limite=' + IP_DEVICE_ANOMALY_MIN + ', aviso 1x/dia');
          }
        }
        if (ipDevicesDia.porIp.size > 5000) ipDevicesDia.porIp.clear(); // defensivo
      }
    } catch (_) {}
  } catch (_) {}
}

/** Registra o device do request no mapa (best-effort, nunca lanca). */
function trackDevice(req, name, uuid) {
  try {
    const dev = devicePayloadFromRequest(req);
    const hwid = dev.v1;
    if (!/^[a-f0-9]{64}$/.test(hwid)) return false; // so o HWID de hardware entra
    const nome = String(name || '').replace(/[\r\n\t]/g, ' ').trim().slice(0, 16);
    const id = String(uuid || '').trim().toLowerCase().slice(0, 40);
    const dados = hwidMapLoad();
    const agora = Date.now();
    const e = dados[hwid] && typeof dados[hwid] === 'object' ? dados[hwid] : { firstSeen: agora, names: [], uuids: [] };
    e.lastSeen = agora;
    if (dev.v2) e.hwid2 = dev.v2;
    if (dev.signed) e.signedAt = agora;
    if (Array.isArray(dev.comps) && dev.comps.length) {
      const set = new Set(Array.isArray(e.comps) ? e.comps : []);
      for (const c of dev.comps) set.add(c);
      e.comps = Array.from(set).slice(-DEVICE_V2_MAX_COMPS);
    }
    if (!Array.isArray(e.names)) e.names = [];
    if (!Array.isArray(e.uuids)) e.uuids = [];
    if (nome && !e.names.includes(nome)) { e.names.push(nome); if (e.names.length > HWID_MAP_HISTORY) e.names.shift(); }
    if (id && !e.uuids.includes(id)) { e.uuids.push(id); if (e.uuids.length > HWID_MAP_HISTORY) e.uuids.shift(); }
    // Contas do device na janela (base da anomalia "muitas contas no mesmo hwid").
    if (!e.accts || typeof e.accts !== 'object') e.accts = {};
    const chaveAcct = id || (nome ? 'name:' + nome.toLowerCase() : '');
    if (chaveAcct) {
      e.accts[chaveAcct] = { n: nome || '', at: agora };
      const chavesAcct = Object.keys(e.accts);
      if (chavesAcct.length > 60) {
        chavesAcct.sort((x, y) => (e.accts[y].at || 0) - (e.accts[x].at || 0)).slice(60).forEach((k) => delete e.accts[k]);
      }
    }
    deviceCheckAnomaly(hwid, e, req);
    dados[hwid] = e;
    const chaves = Object.keys(dados);
    if (chaves.length > HWID_MAP_MAX) {
      chaves.sort((a, b) => (dados[b].lastSeen || 0) - (dados[a].lastSeen || 0)).slice(HWID_MAP_MAX).forEach((k) => delete dados[k]);
    }
    hwidMapDirty = true;
    return true;
  } catch (_) { return false; }
}

/** GET /api/admin/hwid-map — dono consulta o mapa (filtros: ?hwid= ?uuid= ?name=). */
app.get('/api/admin/hwid-map', requireAdmin, (req, res) => {
  try {
    hwidMapFlush();
    const dados = hwidMapLoad();
    const qHwid = String(req.query.hwid || '').trim().toLowerCase();
    const qHwid2 = String(req.query.hwid2 || '').trim().toLowerCase();
    const qUuid = String(req.query.uuid || '').trim().toLowerCase();
    const qName = String(req.query.name || '').trim().toLowerCase();
    const lista = [];
    for (const [hwid, info] of Object.entries(dados)) {
      if (qHwid && hwid !== qHwid) continue;
      if (qHwid2 && String(info.hwid2 || '').toLowerCase() !== qHwid2) continue;
      if (qUuid && !(Array.isArray(info.uuids) && info.uuids.some((u) => String(u).toLowerCase().includes(qUuid)))) continue;
      if (qName && !(Array.isArray(info.names) && info.names.some((n) => String(n).toLowerCase() === qName))) continue;
      lista.push({
        hwid,
        hwid2: String(info.hwid2 || ''),
        comps: Array.isArray(info.comps) ? info.comps : [],
        signed: !!info.signedAt,
        contasJanela: Math.max(0, Math.floor(Number(info.acctsJanela) || 0)),
        contasTotal: (info.accts && typeof info.accts === 'object') ? Object.keys(info.accts).length : 0,
        firstSeen: info.firstSeen || 0,
        lastSeen: info.lastSeen || 0,
        names: info.names || [],
        uuids: info.uuids || []
      });
    }
    lista.sort((a, b) => (b.lastSeen || 0) - (a.lastSeen || 0));
    res.json({ ok: true, count: lista.length, entries: lista.slice(0, 200) });
  } catch (_) {
    try { res.status(500).json({ ok: false, error: 'hwid_map_read_failed' }); } catch (_2) {}
  }
});

/** GET /api/admin/device-anomalies — ultimas anomalias de device (arquivo). */
app.get('/api/admin/device-anomalies', requireAdmin, (req, res) => {
  try {
    let lista = [];
    try { if (fs.existsSync(DEVICE_ANOMALY_FILE)) { const b = JSON.parse(fs.readFileSync(DEVICE_ANOMALY_FILE, 'utf-8')); if (Array.isArray(b)) lista = b; } } catch (_) { lista = []; }
    const limit = Math.min(200, Math.max(1, parseInt(req.query.limit || '80', 10) || 80));
    res.json({ ok: true, count: lista.length, anomalies: lista.slice(0, limit) });
  } catch (_) {
    try { res.status(500).json({ ok: false, error: 'device_anomalies_read_failed' }); } catch (_2) {}
  }
});

/**
 * F17 — GET/POST /api/admin/validate-host — valida alvo de "status de servidor".
 * O backend expoe a MESMA regra canonica (hostguard) que o launcher usa, para
 * operacao/painel e para provar o comportamento. Bloqueia loopback, faixas
 * privadas/link-local/CGNAT e portas que nao sao de Minecraft.
 */
function hostValidateHandler(req, res) {
  try {
    const endereco = String((req.body && req.body.address) || req.query.address || '').trim();
    const check = hostguard.isAllowedMinecraftTarget(endereco);
    res.status(check.ok ? 200 : 400).json({
      ok: check.ok,
      address: endereco.slice(0, 120),
      host: check.host || null,
      port: check.port || null,
      error: check.error || null,
      policy: {
        defaultPort: hostguard.DEFAULT_PORT,
        blocked: ['loopback', 'privado (10/8, 172.16/12, 192.168/16)', 'link-local (169.254/16)', 'CGNAT (100.64/10)', 'multicast/reservado', 'IPv6 fc00::/7, fe80::/10, ::1', 'nomes locais (*.local, localhost, *.lan)', 'portas < 1024 e portas de servico conhecidas']
      }
    });
  } catch (_) {
    res.status(500).json({ ok: false, error: 'validate_failed' });
  }
}
app.get('/api/admin/validate-host', requireAdmin, hostValidateHandler);
app.post('/api/admin/validate-host', requireAdmin, hostValidateHandler);

/** GET /api/admin/ranking-time — visao crua do TOP TEMPO (inclui anomalias por conta). */
app.get('/api/admin/ranking-time', requireAdmin, (req, res) => {
  try {
    const dados = readRankingTime();
    const lista = Object.entries(dados)
      .map(([uuid, info]) => ({ uuid, name: info.name, ms: info.ms, updatedAt: info.updatedAt, lastCreditAt: info.lastCreditAt, lastReportMs: info.lastReportMs, day: info.day, anomalies: info.anomalies }))
      .sort((a, b) => b.ms - a.ms);
    const limit = Math.min(200, Math.max(1, parseInt(req.query.limit || '80', 10) || 80));
    res.json({ ok: true, count: lista.length, entries: lista.slice(0, limit) });
  } catch (_) {
    try { res.status(500).json({ ok: false, error: 'ranking_read_failed' }); } catch (_2) {}
  }
});

/** GET /api/admin/ranking-anomalies — ultimas anomalias do TOP TEMPO (arquivo). */
app.get('/api/admin/ranking-anomalies', requireAdmin, (req, res) => {
  try {
    let lista = [];
    try { if (fs.existsSync(RANKING_ANOMALY_FILE)) { const b = JSON.parse(fs.readFileSync(RANKING_ANOMALY_FILE, 'utf-8')); if (Array.isArray(b)) lista = b; } } catch (_) { lista = []; }
    const limit = Math.min(200, Math.max(1, parseInt(req.query.limit || '80', 10) || 80));
    res.json({ ok: true, count: lista.length, anomalies: lista.slice(0, limit) });
  } catch (_) {
    try { res.status(500).json({ ok: false, error: 'anomalies_read_failed' }); } catch (_2) {}
  }
});

// ---------- Top Tempo (ranking global de tempo de uso) — SERVER-AUTHORITATIVE ----------
// Endpoints:
//   POST /api/ranking/time  { uuid, name, ms }  -> ms = TOTAL acumulado (o launcher manda
//                              o total dele; o SERVIDOR decide quanto creditar)
//   GET  /api/ranking/time?limit=20             -> ranking (pos, name, ms, updatedAt)
// Dados: <data>/ranking-time.json = { "<uuid>": { name, ms, updatedAt, lastCreditAt,
//        lastReportMs, day: { windowStart, credited }, anomalies: [...] } }
//
// SEGURANCA (fix 2026-09-30): o tempo e do SERVIDOR. O cliente NAO seta o total:
//   - credito = min(aumento_pedido, tempo_real_desde_o_ultimo_credito + folga);
//     ou seja, um reporte sobe o total, no maximo, ~o tempo de relogio que passou
//     (aumento absurdo e TRUNCADO e vira anomalia).
//   - catch-up limitado: no maximo 6h + folga por reporte (rede caiu etc).
//   - teto diario: no maximo 26h creditadas por janela movel de 24h por conta.
//   - primeira aparicao (uuid desconhecido): semente de no maximo 6h; o excedente
//     NUNCA e creditado depois.
//   - rate limit por IP REAL (clientKey) e por CONTA (uuid).
//   - anomalias (salto de tempo / teto diario / semente alta) vao para
//     <data>/ranking-anomalies.json + webhook do Guard (dedupe de 10 min).
//   - conta banida (nick/uuid/HWID) nao reporta: 403.
// O arquivo nunca derruba o servidor; leitura/escrita com fila e troca atomica.
const RANKING_TIME_FILE = path.join(DATA_DIR, 'ranking-time.json');
const RANKING_ANOMALY_FILE = path.join(DATA_DIR, 'ranking-anomalies.json');
const RANKING_TIME_MAX_TOTAL_MS = 100 * 365 * 24 * 60 * 60 * 1000; // sanidade do payload (100 anos)
const RANKING_TIME_WINDOW_MS = 60 * 1000;                          // 1 reporte por IP a cada ~60s
const RANKING_TIME_UUID_WINDOW_MS = 45 * 1000;                     // 1 reporte por conta a cada ~45s
const RANKING_TIME_MAX_ENTRIES = 5000;                             // teto defensivo do arquivo
const RANKING_CREDIT_SLACK_MS = 30 * 1000;                         // folga por reporte (latencia/relogio)
const RANKING_CREDIT_MAX_SPAN_MS = 6 * 60 * 60 * 1000;             // catch-up maximo entre reportes
const RANKING_DAY_MS = 24 * 60 * 60 * 1000;                        // janela movel do teto diario
const RANKING_DAY_MAX_MS = 26 * 60 * 60 * 1000;                    // teto creditavel por janela (24h + 2h de folga)
const RANKING_SEED_MAX_MS = 6 * 60 * 60 * 1000;                    // 1a aparicao: teto da semente
// ---- F05 (revisao anti-fraude, 2026-10-01) --------------------------------
// Brechas encontradas revisando o fix anterior com olhos de atacante:
//  (a) o TETO DIARIO era POR UUID: criar N uuids multiplicava o orcamento e
//      enchia o TOP 20 com sementes de 6h cada. Agora existe teto diario por
//      HARDWARE (X-Reality-Device) e por IP, alem do teto por conta, e a
//      primeira aparicao ganha uma semente AUDITADA de no maximo 30 min (o
//      resto so entra por tempo de relogio real, que e o que o servidor mede).
//  (b) o tempo creditado tem que ser INCREMENTAL DE VERDADE: o servidor nunca
//      usa o "ms" do cliente como total — ele so credita min(pedido,
//      tempo_real_desde_o_ultimo_credito + folga), agora ainda limitado pelo
//      teto por hardware/IP do dia.
//  (c) padroes anomalos viram registro: muitos heartbeats (rate limit batido),
//      muitos uuid no mesmo hwid, muitos uuid no mesmo IP, intervalo curto.
//  (d) rate limit GLOBAL (nao-chaveado) no endpoint, como segunda camada.
const RANKING_SEED_FIRST_MS = Math.max(60_000, Math.floor(Number(process.env.RANKING_SEED_FIRST_MS) || 30 * 60 * 1000));
const RANKING_FACET_FILE = path.join(DATA_DIR, 'ranking-facets.json');
const RANKING_HWID_DAY_MAX_MS = Math.max(60 * 60 * 1000, Math.floor(Number(process.env.RANKING_HWID_DAY_MAX_MS) || 26 * 60 * 60 * 1000));
const RANKING_IP_DAY_MAX_MS = Math.max(60 * 60 * 1000, Math.floor(Number(process.env.RANKING_IP_DAY_MAX_MS) || 48 * 60 * 60 * 1000));
const RANKING_HWID_MAX_UUIDS = Math.max(1, Math.floor(Number(process.env.RANKING_HWID_MAX_UUIDS) || 2));
const RANKING_IP_MAX_UUIDS = Math.max(1, Math.floor(Number(process.env.RANKING_IP_MAX_UUIDS) || 6));
const RANKING_FACET_MAX_KEYS = 20_000;
const RANKING_GLOBAL_MAX_PER_MIN = Math.max(30, Math.floor(Number(process.env.RANKING_GLOBAL_MAX_PER_MIN) || 300));

/** Anomalias locais com dedupe em memoria (evita 1 arquivo por request abusivo). */
const rankingAnomalyLocalDedupe = new Map(); // uuid|reason -> ts
function rankingAnomalyRecordThrottled(uuid, name, reason, detail, ms) {
  const chave = String(uuid) + '|' + String(reason);
  const agora = Date.now();
  const janela = Math.max(60_000, Math.floor(Number(ms) || 10 * 60 * 1000));
  if (agora - (rankingAnomalyLocalDedupe.get(chave) || 0) < janela) return null;
  rankingAnomalyLocalDedupe.set(chave, agora);
  if (rankingAnomalyLocalDedupe.size > 2000) {
    for (const [k, t] of rankingAnomalyLocalDedupe) { if (agora - t > janela) rankingAnomalyLocalDedupe.delete(k); }
  }
  return rankingAnomalyRecord(uuid, name, reason, detail);
}

/**
 * F05 (a/c) — tetos por HARDWARE e por IP (janela movel de 24h) + deteccao de
 * "muitos uuid no mesmo hwid/ip". Consome o credito pedido (o menor entre conta,
 * hwid e ip) e grava o uuid que recebeu credito em cada dimensao. Escrita atomica.
 * Retorna { creditado, hwid, ip }.
 */
function rankingFacetApply(req, uuid, name, pedido) {
  const agora = Date.now();
  let hwid = '';
  try {
    const dev = devicePayloadFromRequest(req);
    hwid = String((dev && (dev.hwid || dev.v1)) || req.headers['x-reality-device'] || '').trim().toLowerCase().slice(0, 64);
  } catch (_) {
    hwid = String(req.headers['x-reality-device'] || '').trim().toLowerCase().slice(0, 64);
  }
  if (!/^[a-f0-9]{16,64}$/.test(hwid)) hwid = '';
  const ip = clientKey(req);

  let dados = { hwid: {}, ip: {} };
  try {
    if (fs.existsSync(RANKING_FACET_FILE)) {
      const b = JSON.parse(fs.readFileSync(RANKING_FACET_FILE, 'utf-8'));
      if (b && typeof b === 'object' && !Array.isArray(b)) dados = { hwid: b.hwid || {}, ip: b.ip || {} };
    }
  } catch (_) { dados = { hwid: {}, ip: {} }; }

  let restante = Math.max(0, Math.floor(Number(pedido) || 0));

  function consumir(mapa, id, teto, tetoUuids, rotulo) {
    if (!id) return;
    const r = mapa[id] && typeof mapa[id] === 'object' ? mapa[id] : {};
    let dia = (r.day && typeof r.day === 'object') ? r.day : { windowStart: 0, credited: 0 };
    if (!dia.windowStart || agora - dia.windowStart > RANKING_DAY_MS) dia = { windowStart: agora, credited: 0 };
    const uuids = (r.uuids && typeof r.uuids === 'object' && !Array.isArray(r.uuids)) ? r.uuids : {};
    const jaCreditado = Math.max(0, Math.floor(Number(dia.credited) || 0));
    const sobra = Math.max(0, teto - jaCreditado);
    const permitido = Math.min(restante, sobra);
    if (permitido < restante) {
      rankingAnomalyRecordThrottled(uuid, name, 'teto_' + rotulo,
        'pediu +' + Math.round(restante / 1000) + 's; sobra do dia por ' + rotulo + ' ' + Math.round(sobra / 1000) + 's (' + Object.keys(uuids).length + ' uuid(s) nesse ' + rotulo + ')');
    }
    if (!uuids[uuid]) uuids[uuid] = agora;
    const qtdUuids = Object.keys(uuids).length;
    if (qtdUuids > tetoUuids) {
      rankingAnomalyRecordThrottled(uuid, name, 'muitos_uuid_por_' + rotulo,
        qtdUuids + ' uuid(s) com credito no mesmo ' + rotulo + ' em 24h (limite ' + tetoUuids + ')');
    }
    mapa[id] = { day: { windowStart: dia.windowStart, credited: jaCreditado + permitido }, uuids };
    restante = permitido;
  }

  consumir(dados.hwid, hwid, RANKING_HWID_DAY_MAX_MS, RANKING_HWID_MAX_UUIDS, 'hwid');
  consumir(dados.ip, ip, RANKING_IP_DAY_MAX_MS, RANKING_IP_MAX_UUIDS, 'ip');

  try {
    for (const dim of ['hwid', 'ip']) {
      const chaves = Object.keys(dados[dim]);
      if (chaves.length > RANKING_FACET_MAX_KEYS) {
        chaves.sort((a, b) => ((dados[dim][a].day && dados[dim][a].day.windowStart) || 0) - ((dados[dim][b].day && dados[dim][b].day.windowStart) || 0));
        chaves.slice(0, chaves.length - RANKING_FACET_MAX_KEYS).forEach((k) => { delete dados[dim][k]; });
      }
    }
    const tmp = RANKING_FACET_FILE + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(dados, null, 2), 'utf-8');
    fs.renameSync(tmp, RANKING_FACET_FILE);
  } catch (_) {}
  return { creditado: restante, hwid, ip };
}

/** F05 (c) — cadencia: reportes que PASSAM no rate limit sao contados por conta. */
const rankingCadence = new Map(); // uuid -> [ts]
function rankingCadenceNote(uuid, name) {
  const agora = Date.now();
  const hist = (rankingCadence.get(uuid) || []).filter((t) => agora - t < 60_000);
  if (hist.length >= 3) {
    rankingAnomalyRecordThrottled(uuid, name, 'heartbeat_excessivo', hist.length + 1 + ' reportes aceitos em 60s (o limite da conta e 1/45s) — cliente modificado ou multi-IP');
  } else if (hist.length) {
    const gap = agora - hist[hist.length - 1];
    if (gap < 10_000) {
      rankingAnomalyRecordThrottled(uuid, name, 'intervalo_irregular', 'reporte ' + Math.round(gap / 1000) + 's depois do anterior (limite da conta: 45s) — multi-IP');
    }
  }
  hist.push(agora);
  rankingCadence.set(uuid, hist);
  if (rankingCadence.size > 20_000) {
    const sobra = rankingCadence.size - 20_000;
    let i = 0;
    for (const k of rankingCadence.keys()) { if (i++ >= sobra) break; rankingCadence.delete(k); }
  }
}
const RANKING_TRUNC_EPS_MS = 60 * 1000;                            // truncou > 1 min => anomalia
const RANKING_ANOMALY_MAX = 500;
let rankingTimeQueue = Promise.resolve();

function withRankingTimeLock(task) {
  const result = rankingTimeQueue.then(task, task);
  rankingTimeQueue = result.catch(() => {});
  return result;
}

function readRankingTime() {
  try {
    if (!fs.existsSync(RANKING_TIME_FILE)) return {};
    const bruto = JSON.parse(fs.readFileSync(RANKING_TIME_FILE, 'utf-8'));
    if (!bruto || typeof bruto !== 'object' || Array.isArray(bruto)) return {};
    const limpo = {};
    for (const [uuid, info] of Object.entries(bruto)) {
      try {
        if (!info || typeof info !== 'object') continue;
        // Chave e nome no MESMO formato que o POST aceita: entrada fora do
        // padrao (arquivo editado na mao / corrompido) e descartada.
        if (!/^[0-9a-fA-F-]{32,36}$/.test(String(uuid))) continue;
        const ms = Math.floor(Number(info.ms));
        if (!Number.isFinite(ms) || ms <= 0) continue;
        const name = String(info.name || '').trim();
        if (!/^[A-Za-z0-9_]{1,16}$/.test(name)) continue;
        const diaBruto = (info.day && typeof info.day === 'object') ? info.day : {};
        limpo[String(uuid)] = {
          name,
          ms,
          // base = baseline da TEMPORADA (reset do TOP TEMPO): o valor exibido no
          // ranking é ms - base; o ms bruto continua guardando o total de sempre.
          base: Math.max(0, Math.floor(Number(info.base) || 0)),
          updatedAt: Math.max(0, Math.floor(Number(info.updatedAt) || 0)),
          lastCreditAt: Math.max(0, Math.floor(Number(info.lastCreditAt) || 0)),
          lastReportMs: Math.max(0, Math.floor(Number(info.lastReportMs) || 0)),
          day: {
            windowStart: Math.max(0, Math.floor(Number(diaBruto.windowStart) || 0)),
            credited: Math.max(0, Math.floor(Number(diaBruto.credited) || 0))
          },
          anomalies: Array.isArray(info.anomalies) ? info.anomalies.slice(-10).map((a) => ({
            at: Math.max(0, Math.floor(Number(a && a.at) || 0)),
            reason: String((a && a.reason) || '').slice(0, 40),
            detail: String((a && a.detail) || '').slice(0, 160)
          })) : []
        };
      } catch (_) { /* entrada invalida: ignora */ }
    }
    return limpo;
  } catch (_) {
    return {}; // arquivo ausente/corrompido => recomeca vazio
  }
}

function writeRankingTime(dados) {
  try {
    if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
    const tempFile = `${RANKING_TIME_FILE}.tmp`;
    fs.writeFileSync(tempFile, JSON.stringify(dados, null, 2), 'utf-8');
    fs.renameSync(tempFile, RANKING_TIME_FILE); // troca atomica (igual ao manifesto)
    return true;
  } catch (_) {
    return false;
  }
}

// ---- anomalias: arquivo + webhook do Guard ----
let rankingAnomalyQueue = Promise.resolve();
const rankingAnomalyWebhookDedupe = new Map(); // uuid|reason -> ultimo envio
let rankingAnomalyWebhookWindow = { start: 0, count: 0 };
const RANKING_ANOMALY_WEBHOOK_DEDUPE_MS = 10 * 60 * 1000;
const RANKING_ANOMALY_WEBHOOK_MAX_PER_MIN = 6;

function rankingAnomalyRecord(uuid, name, reason, detail) {
  const registro = {
    at: Date.now(),
    uuid: String(uuid || '').slice(0, 40),
    name: String(name || '').slice(0, 16),
    reason: String(reason || '').slice(0, 40),
    detail: String(detail || '').slice(0, 160)
  };
  rankingAnomalyQueue = rankingAnomalyQueue.catch(() => {}).then(() => {
    try {
      let lista = [];
      try {
        if (fs.existsSync(RANKING_ANOMALY_FILE)) {
          const b = JSON.parse(fs.readFileSync(RANKING_ANOMALY_FILE, 'utf-8'));
          if (Array.isArray(b)) lista = b;
        }
      } catch (_) { lista = []; }
      lista.unshift(registro);
      if (lista.length > RANKING_ANOMALY_MAX) lista.length = RANKING_ANOMALY_MAX;
      const tempFile = `${RANKING_ANOMALY_FILE}.tmp`;
      fs.writeFileSync(tempFile, JSON.stringify(lista, null, 2), 'utf-8');
      fs.renameSync(tempFile, RANKING_ANOMALY_FILE);
    } catch (_) {}
  });
  try { console.log('[ranking] anomalia', registro.name || registro.uuid, registro.reason, '|', registro.detail.slice(0, 120)); } catch (_) {}
  try { rankingAnomalyWebhook(registro); } catch (_) {}
  return registro;
}

function rankingAnomalyWebhook(registro) {
  const url = guardWebhookUrl();
  if (!url) return 'disabled';
  const chave = String(registro.uuid) + '|' + registro.reason;
  const agora = Date.now();
  if (agora - (rankingAnomalyWebhookDedupe.get(chave) || 0) < RANKING_ANOMALY_WEBHOOK_DEDUPE_MS) return 'deduped';
  if (agora - rankingAnomalyWebhookWindow.start > 60000) rankingAnomalyWebhookWindow = { start: agora, count: 0 };
  if (rankingAnomalyWebhookWindow.count >= RANKING_ANOMALY_WEBHOOK_MAX_PER_MIN) return 'throttled';
  rankingAnomalyWebhookDedupe.set(chave, agora);
  if (rankingAnomalyWebhookDedupe.size > 500) {
    for (const [k, t] of rankingAnomalyWebhookDedupe) { if (agora - t > RANKING_ANOMALY_WEBHOOK_DEDUPE_MS) rankingAnomalyWebhookDedupe.delete(k); }
  }
  rankingAnomalyWebhookWindow.count += 1;
  guardWebhookPost(url, {
    username: 'Reality Guard',
    embeds: [{
      title: '🚨 TOP TEMPO — anomalia de tempo',
      color: 0xE74C3C,
      fields: [
        { name: 'Jogador', value: '`' + (registro.name || '?') + '`', inline: true },
        { name: 'UUID', value: '`' + registro.uuid + '`', inline: true },
        { name: 'Tipo', value: '`' + registro.reason + '`', inline: true },
        { name: 'Detalhe', value: registro.detail.slice(0, 400) || '—', inline: false },
        { name: 'Horario (Brasilia)', value: guardBrasiliaTime(registro.at), inline: true }
      ],
      footer: { text: 'top tempo anti-fraude (server-authoritative)' }
    }]
  }).catch(() => {});
  return 'sent';
}

app.post('/api/ranking/time', (req, res) => {
  try {
    const body = req.body || {};
    const uuid = String(body.uuid || '').trim();
    const name = String(body.name || '').trim();
    const ms = Number(body.ms);
    if (!/^[0-9a-fA-F-]{32,36}$/.test(uuid)) {
      return res.status(400).json({ ok: false, error: 'invalid_uuid' });
    }
    if (!/^[A-Za-z0-9_]{1,16}$/.test(name)) {
      return res.status(400).json({ ok: false, error: 'invalid_name' });
    }
    // ms = TOTAL acumulado reportado pelo launcher (so um teto de sanidade do payload).
    if (!Number.isFinite(ms) || !Number.isInteger(ms) || ms <= 0 || ms > RANKING_TIME_MAX_TOTAL_MS) {
      return res.status(400).json({ ok: false, error: 'invalid_ms' });
    }
    // BAN: conta/HWID banido nao reporta.
    const banido = banCheckRequest(req, null);
    if (banido) return res.status(403).json(banBlockBody(banido));
    const key = normalizeUuid(uuid);
    // rate limit por IP REAL (clientKey) e por CONTA.
    if (!rateLimit(clientKey(req), 'ranking-time', 1, RANKING_TIME_WINDOW_MS)) {
      rankingAnomalyRecordThrottled(key, name, 'heartbeat_excesso', 'rate limit de IP batido no POST /api/ranking/time (mais de 1 reporte/60s) — cliente modificado ou multi-IP');
      return res.status(429).json({ ok: false, error: 'too_many_reports' });
    }
    if (!rateLimit(key, 'ranking-time-uuid', 1, RANKING_TIME_UUID_WINDOW_MS)) {
      rankingAnomalyRecordThrottled(key, name, 'heartbeat_excesso', 'rate limit da CONTA batido no POST /api/ranking/time (mais de 1 reporte/45s) — cliente modificado');
      return res.status(429).json({ ok: false, error: 'too_many_reports' });
    }
    // F05 (d): teto GLOBAL (nao-chaveado) do endpoint — segunda camada, para que
    // trocar de IP/uuid nao derrube o servidor a force de gravacao do arquivo.
    if (!rateLimit('*global*', 'ranking-time-global', RANKING_GLOBAL_MAX_PER_MIN, 60000)) {
      return res.status(429).json({ ok: false, error: 'too_many_reports', scope: 'global' });
    }
    try { trackDevice(req, name, key); } catch (_) {}
    withRankingTimeLock(() => {
      const dados = readRankingTime();
      const agora = Date.now();
      const prev = dados[key] || null;
      let total = 0;
      let creditado = 0;
      if (!prev) {
        // 1a aparicao pos-fix: semente AUDITADA (excedente nunca e creditado
        // depois). Antes eram ate 6h de graca por uuid novo — criar N uuids
        // enchia o TOP 20. Agora sao no maximo RANKING_SEED_FIRST_MS e o resto
        // so entra por TEMPO DE RELOGIO real (heartbeat incremental).
        total = Math.min(Math.floor(ms), RANKING_SEED_MAX_MS, RANKING_SEED_FIRST_MS);
        creditado = total;
        dados[key] = {
          name,
          ms: total,
          base: 0,
          updatedAt: agora,
          lastCreditAt: agora,
          lastReportMs: Math.floor(ms),
          day: { windowStart: agora, credited: total },
          anomalies: []
        };
        if (ms > RANKING_SEED_FIRST_MS) {
          rankingAnomalyRecord(key, name, 'semente_alta',
            'primeiro reporte pediu ' + Math.floor(ms / 1000) + 's; teto de semente ' + Math.floor(RANKING_SEED_FIRST_MS / 1000) + 's; aceitos ' + Math.floor(total / 1000) + 's');
        }
      } else {
        const baseline = Math.max(
          Math.floor(Number(prev.lastReportMs) || 0),
          Math.floor(Number(prev.ms) || 0)
        );
        const aumentoPedido = Math.floor(ms) - baseline; // >0 = pediu tempo novo
        const ultimoCredito = Math.floor(Number(prev.lastCreditAt) || 0);
        const elapsed = ultimoCredito > 0 ? Math.max(0, agora - ultimoCredito) : 0;
        const permissaoBase = Math.min(elapsed, RANKING_CREDIT_MAX_SPAN_MS) + RANKING_CREDIT_SLACK_MS;
        let dia = (prev.day && typeof prev.day === 'object') ? prev.day : { windowStart: 0, credited: 0 };
        if (!dia.windowStart || agora - dia.windowStart > RANKING_DAY_MS) dia = { windowStart: agora, credited: 0 };
        const creditedBruto = Math.max(0, Math.floor(Number(dia.credited) || 0));
        const sobraDia = Math.max(0, RANKING_DAY_MAX_MS - creditedBruto);
        const permissao = Math.min(permissaoBase, sobraDia);
        if (aumentoPedido > 0) creditado = Math.max(0, Math.min(aumentoPedido, permissao));
        total = Math.max(0, Math.floor(Number(prev.ms) || 0)) + creditado;
        const truncado = Math.max(0, aumentoPedido - creditado);
        if (truncado > RANKING_TRUNC_EPS_MS) {
          const motivo = sobraDia <= permissaoBase ? 'teto_dia' : 'salto_tempo';
          const registro = rankingAnomalyRecord(key, name, motivo,
            'pediu +' + Math.round(aumentoPedido / 1000) + 's (total ' + Math.floor(ms / 1000) + 's); permitido +' + Math.round(permissao / 1000) + 's (janela ' + Math.round(elapsed / 1000) + 's; sobra do dia ' + Math.round(sobraDia / 1000) + 's); creditado +' + Math.round(creditado / 1000) + 's; truncado ' + Math.round(truncado / 1000) + 's');
          try {
            if (!Array.isArray(prev.anomalies)) prev.anomalies = [];
            prev.anomalies.push({ at: registro.at, reason: registro.reason, detail: registro.detail });
            if (prev.anomalies.length > 10) prev.anomalies = prev.anomalies.slice(-10);
          } catch (_) {}
        } else if (aumentoPedido < -5 * 60 * 1000) {
          // regressao grande (ex.: config apagado/maquina nova): registra sem bloquear
          try {
            if (!Array.isArray(prev.anomalies)) prev.anomalies = [];
            prev.anomalies.push({ at: agora, reason: 'regressao', detail: 'reporte de ' + Math.floor(ms / 1000) + 's; servidor tinha ' + Math.floor(baseline / 1000) + 's' });
            if (prev.anomalies.length > 10) prev.anomalies = prev.anomalies.slice(-10);
          } catch (_) {}
        }
        prev.name = name;
        prev.ms = total;
        prev.base = Math.max(0, Math.floor(Number(prev.base) || 0));
        prev.updatedAt = agora;
        prev.lastReportMs = Math.max(baseline, Math.floor(ms));
        if (creditado > 0) prev.lastCreditAt = agora;
        prev.day = { windowStart: dia.windowStart, credited: creditedBruto + creditado };
        dados[key] = prev;
      }
      // ---- F05 (a): teto por HARDWARE e por IP ----
      // O credito acima e limitado pela CONTA (janela real + teto diario). Aqui a
      // mesma pergunta e feita por HARDWARE e por IP: criar varios uuid nao
      // multiplica o orcamento. O corte vira anomalia (teto_hwid / teto_ip) e o
      // "dia" da conta e ajustado para refletir so o que entrou de verdade.
      if (creditado > 0) {
        try {
          const facet = rankingFacetApply(req, key, name, creditado);
          const permitido = Math.max(0, Math.floor(Number(facet.creditado) || 0));
          if (permitido < creditado) {
            const cortado = creditado - permitido;
            creditado = permitido;
            total = Math.max(0, total - cortado);
            const alvo = dados[key];
            if (alvo && alvo.day && typeof alvo.day === 'object') {
              alvo.day.credited = Math.max(0, Math.floor(Number(alvo.day.credited) || 0) - cortado);
            }
            if (alvo) {
              alvo.lastReportMs = Math.min(Math.floor(Number(alvo.lastReportMs) || 0), Math.floor(ms));
            }
          }
        } catch (_) {}
        try { rankingCadenceNote(key, name); } catch (_) {}
      }
      const chaves = Object.keys(dados);
      if (chaves.length > RANKING_TIME_MAX_ENTRIES) {
        // Teto defensivo: mantem so os maiores tempos.
        const maiores = chaves.sort((a, b) => dados[b].ms - dados[a].ms).slice(0, RANKING_TIME_MAX_ENTRIES);
        const reduzido = {};
        for (const k of maiores) reduzido[k] = dados[k];
        writeRankingTime(reduzido);
      } else {
        writeRankingTime(dados);
      }
      return { total, creditado, base: Math.max(0, Math.floor(Number(dados[key] && dados[key].base) || 0)) };
    }).then((r) => {
      // ms da resposta = TEMPORADA (ms bruto - baseline do reset), igual ao GET.
      try { res.json({ ok: true, ms: Math.max(0, r.total - r.base), credited: r.creditado }); } catch (_) {}
    }).catch(() => {
      try { res.status(500).json({ ok: false, error: 'ranking_save_failed' }); } catch (_) {}
    });
  } catch (e) {
    try { res.status(500).json({ ok: false, error: 'ranking_report_failed' }); } catch (_) {}
  }
});

app.get('/api/ranking/time', (req, res) => {
  try {
    res.setHeader('Cache-Control', 'no-store');
    const pedido = parseInt(req.query.limit, 10);
    const limit = Math.min(50, Math.max(1, Number.isFinite(pedido) ? pedido : 20));
    const dados = readRankingTime();
    const lista = Object.entries(dados)
      .map(([uuid, info]) => ({
        name: info.name,
        // valor da TEMPORADA (o reset do TOP TEMPO grava base = total antigo)
        ms: Math.max(0, info.ms - Math.max(0, Math.floor(Number(info.base) || 0))),
        updatedAt: info.updatedAt || 0
      }))
      .sort((a, b) => (b.ms - a.ms) || (a.updatedAt - b.updatedAt) || String(a.name).localeCompare(String(b.name)));
    const top = lista.slice(0, limit).map((item, i) => ({ name: item.name, ms: item.ms, updatedAt: item.updatedAt || 0, pos: i + 1 }));
    res.json({ ok: true, top, total: lista.length });
  } catch (e) {
    try { res.status(500).json({ ok: false, error: 'ranking_read_failed', top: [], total: 0 }); } catch (_) {}
  }
});


// ---------- MOEDAS server-authoritative (saldo / earn / spend por conta) ----------
// A economia (saldo + posse) vive AQUI: <data>/coins.json. O config.json do
// launcher DEIXOU de ser fonte de verdade — editar o arquivo local não credita
// nada, porque quem credita é este servidor (tick de tempo com cooldown e teto
// por conta) e quem valida a compra é o catálogo de preços daqui.
//
// Endpoints:
//   GET  /api/coins        -> saldo + capas/selos comprados + catálogo de preços
//   POST /api/coins/earn   -> { event: 'launcher'|'game' } => no MÁX. +5 a cada 5 min
//   POST /api/coins/spend  -> { item, tipo: 'cape'|'seal', requestId } (idempotente)
//
// Identidade: token social (Authorization: Bearer) quando houver — a conta é a
// dona do token (social.findUserByToken) — senão a conta offline/uuid (mesmo
// modelo do Top Tempo: X-Reality-Uuid / X-Reality-Name).
//
// SEGURANCA: nenhum endpoint aceita valor de moeda vindo do cliente (amount,
// coins, price são IGNORADOS); só o TIPO do evento de earn e o ITEM comprado.
// Rate limit por IP REAL (clientKey) + cooldown/teto por conta; escrita atômica
// (tmp + rename) e fila (withCoinsLock) como no ranking/manifesto.
//
// MIGRACAO: saldo legado do config.json do launcher NÃO entra na economia
// (migratedFromLocalConfig = false). Contas começam em zero aqui e ganham de
// novo pelo servidor; o launcher só reporta o valor local para o Guard.
const COINS_FILE = path.join(DATA_DIR, 'coins.json');
const COINS_EARN_INTERVAL_MS = 5 * 60 * 1000; // 1 crédito a cada 5 min (mesma economia de hoje)
const COINS_EARN_AMOUNT = 5;                  // +5 moedas por crédito
const COINS_EARN_MAX_PER_HOUR = 12;           // teto/hora (60 moedas/h)
const COINS_EARN_MAX_PER_DAY = 240;           // teto/dia (1200 moedas/dia)
const COINS_EARN_EVENTS = new Set(['launcher', 'game']); // só o TIPO do evento
const COINS_MAX_ACCOUNTS = 20000;             // teto defensivo do arquivo
const COINS_MAX_ITEMS = 500;                  // teto de itens por conta
const COINS_MAX_REQUESTS = 50;                // idempotência: últimos N pedidos por conta
const COINS_SPEND_MAX_PER_MIN = 30;           // rate limit por IP nas compras
const COINS_EARN_MAX_PER_MIN = 20;            // rate limit por IP nos earns
let coinsQueue = Promise.resolve();

function withCoinsLock(task) {
  const result = coinsQueue.then(task, task);
  coinsQueue = result.catch(() => {});
  return result;
}

// Catálogo de PREÇOS do servidor — fonte única da verdade na compra.
// Os ids/preços são EXATAMENTE os de hoje no launcher (COIN_CAPE_PRICES e o
// catálogo de selos); o preço que o cliente mandar é ignorado.
//
// FORA DA LOJA (pedido do dono): as 7 capas da COPA saíram do catálogo —
//   capa_copa_noruega, capa_copa_brasil, capa_copa_franca, capa_copa_argentina,
//   capa_copa_espanha, capa_copa_portugal, capa_copa_italia.
// Efeitos: (a) não aparecem mais no catálogo do GET /api/coins; (b) comprar
// qualquer uma delas responde 400 unknown_item (nada é debitado); (c) a POSSE de
// quem já comprou NÃO é tocada — ownedCapes continua como está e é devolvido no
// GET /api/coins, então a capa segue equipável para o dono.
const COIN_CAPE_PRICES = {
  capa_montanha: 30,
  reality_bolt: 50
};
// Capas de LOJA aposentadas (fora de venda, posse preservada). Não entram no
// catálogo de preços — servem só para documentar/checar a aposentadoria.
const COIN_CAPE_RETIRED = [
  'capa_copa_noruega',
  'capa_copa_brasil',
  'capa_copa_franca',
  'capa_copa_argentina',
  'capa_copa_espanha',
  'capa_copa_portugal',
  'capa_copa_italia'
];
// 120 selos do mercado (ids/preços idênticos ao catálogo embutido do launcher).
const COIN_SEAL_PRICES = {"seal_001":25,"seal_002":42,"seal_003":59,"seal_004":40,"seal_005":57,"seal_006":38,"seal_007":70,"seal_008":87,"seal_009":104,"seal_010":192,"seal_011":209,"seal_012":135,"seal_013":303,"seal_014":671,"seal_015":47,"seal_016":28,"seal_017":45,"seal_018":26,"seal_019":43,"seal_020":60,"seal_021":104,"seal_022":70,"seal_023":87,"seal_024":104,"seal_025":174,"seal_026":191,"seal_027":390,"seal_028":256,"seal_029":875,"seal_030":50,"seal_031":31,"seal_032":48,"seal_033":29,"seal_034":46,"seal_035":87,"seal_036":104,"seal_037":70,"seal_038":87,"seal_039":139,"seal_040":156,"seal_041":326,"seal_042":343,"seal_043":662,"seal_044":36,"seal_045":53,"seal_046":34,"seal_047":51,"seal_048":32,"seal_049":49,"seal_050":87,"seal_051":104,"seal_052":70,"seal_053":195,"seal_054":212,"seal_055":138,"seal_056":279,"seal_057":649,"seal_058":58,"seal_059":39,"seal_060":56,"seal_061":37,"seal_062":54,"seal_063":35,"seal_064":70,"seal_065":87,"seal_066":104,"seal_067":160,"seal_068":177,"seal_069":194,"seal_070":366,"seal_071":636,"seal_072":44,"seal_073":25,"seal_074":42,"seal_075":59,"seal_076":40,"seal_077":57,"seal_078":104,"seal_079":70,"seal_080":87,"seal_081":104,"seal_082":142,"seal_083":159,"seal_084":302,"seal_085":319,"seal_086":1042,"seal_087":47,"seal_088":28,"seal_089":45,"seal_090":26,"seal_091":43,"seal_092":87,"seal_093":104,"seal_094":70,"seal_095":87,"seal_096":198,"seal_097":215,"seal_098":141,"seal_099":255,"seal_100":627,"seal_101":33,"seal_102":50,"seal_103":31,"seal_104":48,"seal_105":29,"seal_106":46,"seal_107":87,"seal_108":104,"seal_109":70,"seal_110":163,"seal_111":180,"seal_112":197,"seal_113":342,"seal_114":614,"seal_115":55,"seal_116":36,"seal_117":53,"seal_118":34,"seal_119":51,"seal_120":32};

function coinsCatalog() {
  return { capes: Object.assign({}, COIN_CAPE_PRICES), seals: Object.assign({}, COIN_SEAL_PRICES) };
}

// ---------- Selo exclusivo 'beta_test' (códigos BTSRLY*, uso único) ----------
// Espelho do launcher (src/sealsExclusive.js / src/redeemCatalog.js):
//   * NÃO está à venda: fica FORA do COIN_SEAL_PRICES — POST /api/coins/spend
//     com item 'beta_test' responde 400 not_for_sale (nada é debitado).
//   * A posse SÓ entra pelo resgate de um dos 10 códigos BTSRLY*: o POST
//     /api/redeem grava o id no ownedSeals da CONTA (data/coins.json) — nunca
//     no config.json do jogador.
//   * Cada código vale 1 resgate (usesLeft: 1) e cada CONTA resgata 1 vez.
const BETA_TEST_SEAL_ID = 'beta_test';
// Catálogo de EXCLUSIVOS (arte idêntica à do launcher): vai no GET /api/coins ->
// exclusiveSeals e NUNCA entra em prices.seals (que é só o que está à venda).
const COIN_SEAL_EXCLUSIVE = {
  beta_test: {
    name: 'Beta Test',
    rarity: 'legendary',
    color: '#22c55e',
    color2: '#064e3b',
    gradient: 'linear-gradient(135deg,#4ade80,#22c55e 45%,#0f766e)',
    icon: '✦',
    exclusive: true,
    price: 0,
    forSale: false
  }
};

function coinsExclusiveSeals() {
  const out = {};
  for (const [id, def] of Object.entries(COIN_SEAL_EXCLUSIVE)) out[id] = Object.assign({}, def);
  return out;
}

// ---------- CAPAS EXCLUSIVAS de código (NUNCA estão à venda) ----------
// Espelho de src/redeemCatalog.js + LOCAL_CAPES do renderer. A POSSE só entra
// pelo resgate de um código (`capeId` na entrada do manifest.codes): o POST
// /api/redeem grava o id no ownedCapes da CONTA (data/coins.json). Nada aqui
// entra em COIN_CAPE_PRICES (que é só o que a loja vende).
//   - capa_beta_test        -> 10 códigos BTSRLY* (uso único cada)
//   - capa_reality_display  -> 10 códigos RLTYRED*  (uso único cada)
//   - capa_pindown_cat      -> 1 código (RLTYPINDOWN), PRIVADA: `hidden` = não
//     aparece em catálogo público nenhum, só no ownedCapes de quem resgatou.
const COIN_CAPE_EXCLUSIVE = {
  capa_beta_test: {
    name: 'Beta Test',
    rarity: 'legendary',
    color: '#22c55e',
    color2: '#064e3b',
    gradient: 'linear-gradient(135deg,#4ade80,#22c55e 45%,#0f766e)',
    icon: '✦',
    exclusive: true,
    fromCode: true,
    price: 0,
    forSale: false
  },
  capa_reality_display: {
    name: 'Reality Client',
    rarity: 'legendary',
    color: '#ef4444',
    color2: '#450a0a',
    gradient: 'linear-gradient(135deg,#f87171,#ef4444 45%,#7f1d1d)',
    icon: '✦',
    exclusive: true,
    fromCode: true,
    price: 0,
    forSale: false
  },
  capa_pindown_cat: {
    name: 'Pin Down (animada)',
    rarity: 'mythic',
    color: '#38bdf8',
    color2: '#0c4a6e',
    gradient: 'linear-gradient(135deg,#7dd3fc,#38bdf8 45%,#075985)',
    icon: '✦',
    exclusive: true,
    fromCode: true,
    hidden: true,   // privada do dono: fora do catálogo público
    private: true,
    animated: true,
    price: 0,
    forSale: false
  },
  capa_reality_anim: {
    name: 'Reality (animada)',
    rarity: 'mythic',
    color: '#a78bfa',
    color2: '#2e1065',
    gradient: 'linear-gradient(135deg,#c4b5fd,#8b5cf6 45%,#4c1d95)',
    icon: '✦',
    exclusive: true,
    fromCode: true,
    hidden: true,   // privada do dono: fora do catálogo público
    private: true,
    animated: true,
    price: 0,
    forSale: false
  },
  // TOP TEMPO (prêmio do ranking): concedidas pelo SERVIDOR por 30 DIAS — não são
  // de código (fromCode:false) e ficam fora do catálogo público (hidden). Quem
  // controla a expiração é capesVivasDaConta (capeExpiry na conta).
  capa_top1_tempo: {
    name: 'Top 1 Tempo',
    rarity: 'legendary',
    color: '#fbbf24',
    color2: '#78350f',
    gradient: 'linear-gradient(135deg,#fde68a,#f59e0b 45%,#78350f)',
    icon: '✦',
    exclusive: true,
    fromCode: false,
    hidden: true,
    price: 0,
    forSale: false
  },
  capa_top2_tempo: {
    name: 'Top 2 Tempo',
    rarity: 'legendary',
    color: '#e5e7eb',
    color2: '#334155',
    gradient: 'linear-gradient(135deg,#f1f5f9,#94a3b8 45%,#334155)',
    icon: '✦',
    exclusive: true,
    fromCode: false,
    hidden: true,
    price: 0,
    forSale: false
  },
  capa_top3_tempo: {
    name: 'Top 3 Tempo',
    rarity: 'legendary',
    color: '#d97706',
    color2: '#431407',
    gradient: 'linear-gradient(135deg,#fcd34d,#b45309 45%,#431407)',
    icon: '✦',
    exclusive: true,
    fromCode: false,
    hidden: true,
    price: 0,
    forSale: false
  }
};

/** Catálogo PÚBLICO das capas exclusivas (sem as `hidden`, ex.: a privada). */
function coinsExclusiveCapes() {
  const out = {};
  for (const [id, def] of Object.entries(COIN_CAPE_EXCLUSIVE)) {
    if (def.hidden) continue;
    out[id] = Object.assign({}, def);
  }
  return out;
}

/** Os 10 códigos de USO ÚNICO do selo + CAPA 'Beta Test' (o launcher já os conhece). */
const BETA_TEST_CODES = [
  'BTSRLY10', 'BTSRLY12', 'BTSRLY50', 'BTSRLY42', 'BTSRLY67',
  'BTSRLY2001', 'BTSRLY302', 'BTSRLY163', 'BTSRLY0725', 'BTSRLY5427'
];

/** Os 10 códigos de USO ÚNICO da CAPA vermelha 'REALITY CLIENT'. */
const RED_CAPE_CODES = [
  'RLTYRED01', 'RLTYRED02', 'RLTYRED03', 'RLTYRED04', 'RLTYRED05',
  'RLTYRED06', 'RLTYRED07', 'RLTYRED08', 'RLTYRED09', 'RLTYRED10'
];

/** O código ÚNICO da CAPA ANIMADA privada do dono (não sai em lugar nenhum). */
const ANIMATED_CAPE_CODE = 'RLTYPINDOWN';

/** 1.6.79: código da capa ANIMADA "Reality" (logo) — privada do dono. */
const REALITY_ANIM_CODE = 'RLTYLOGO';

function betaTestCodeEntry() {
  return {
    visual: null,
    badge: 'Beta Test',
    cape: null,
    capeId: 'capa_beta_test', // CAPA verde Beta Test, gravada no ownedCapes da conta
    role: 'Beta Test',
    displayName: null,
    seal: BETA_TEST_SEAL_ID,  // + selo exclusivo 'beta_test' (badge)
    usesLeft: 1,              // uso único: 1 resgate no total
    redeemedBy: []
  };
}

function exclusiveCapeCodeEntry(badge, role, capeId, seal) {
  return {
    visual: null,
    badge,
    cape: null,
    capeId,
    role,
    displayName: null,
    seal: seal || null,
    usesLeft: 1,              // uso único
    redeemedBy: []
  };
}

/**
 * Catálogo dos códigos EXCLUSIVOS (uso único, SEM moedas): [codigo, entrada].
 * Nenhum deles credita moeda — a recompensa é a POSSE na conta (selo e/ou capa).
 */
function exclusiveCodeCatalog() {
  const out = [];
  for (const code of BETA_TEST_CODES) out.push([code, betaTestCodeEntry()]);
  for (const code of RED_CAPE_CODES) {
    out.push([code, exclusiveCapeCodeEntry('Reality Client', 'Reality Client', 'capa_reality_display')]);
  }
  out.push([ANIMATED_CAPE_CODE, exclusiveCapeCodeEntry('Dono do Reality', 'Dono do Reality Client', 'capa_pindown_cat')]);
  // 1.6.79: capa ANIMADA "Reality" (logo). As capas do TOP TEMPO NÃO são de
  // código: o SERVIDOR concede na conta por 30 dias (ver capesVivasDaConta).
  out.push([REALITY_ANIM_CODE, exclusiveCapeCodeEntry('Dono do Reality', 'Dono do Reality Client', 'capa_reality_anim')]);
  return out;
}

/**
 * SEMENTE IDEMPOTENTE (rodada no boot): cria no manifest.codes só os códigos
 * que AINDA NÃO EXISTEM — nunca sobrescreve um código existente (nem para
 * "restaurar" usesLeft/redeemedBy: o que já foi resgatado segue resgatado).
 * MIGRAÇÃO: código que já existia (seed antiga, sem recompensa de capa) ganha
 * só o `capeId`/`seal` que faltar — usesLeft/redeemedBy ficam intactos.
 */
function seedExclusiveCodes() {
  return withRedeemLock(() => {
    const m = readManifest();
    if (!m.codes || typeof m.codes !== 'object' || Array.isArray(m.codes)) m.codes = {};
    const criados = [];
    const migrados = [];
    for (const [code, def] of exclusiveCodeCatalog()) {
      const atual = m.codes[code];
      if (!atual || typeof atual !== 'object' || Array.isArray(atual)) {
        m.codes[code] = def;
        criados.push(code);
        continue;
      }
      let mexeu = false;
      if (def.capeId && atual.capeId !== def.capeId) { atual.capeId = def.capeId; mexeu = true; }
      if (def.seal && atual.seal !== def.seal) { atual.seal = def.seal; mexeu = true; }
      if (mexeu) migrados.push(code);
    }
    if (criados.length || migrados.length) {
      writeManifest(m); // grava atômico (tmp + rename) e atualiza updatedAt/version
      return { created: criados, migrated: migrados };
    }
    return { created: [], migrated: [] };
  });
}

/** Compatibilidade: nome antigo do seed (usado em outras rodadas/scripts). */
function seedBetaTestCodes() {
  return seedExclusiveCodes();
}

function coinsPolicy() {
  return {
    earnIntervalMs: COINS_EARN_INTERVAL_MS,
    earnAmount: COINS_EARN_AMOUNT,
    maxPerHour: COINS_EARN_MAX_PER_HOUR,
    maxPerDay: COINS_EARN_MAX_PER_DAY
  };
}

function coinsDefaultFile() {
  return {
    version: 1,
    // Flags de migração explícitas: o saldo legado do config.json do jogador
    // NUNCA é importado (senão o "coins: 100000000000" editado no arquivo
    // viraria saldo real). Quem nunca ganhou AQUI começa com zero.
    migratedFromLocalConfig: false,
    migrationNote: 'Saldos de config.json do launcher nao migram: a economia comeca zerada por conta e so o servidor credita.',
    policy: coinsPolicy(),
    accounts: {}
  };
}

function coinsSanitizeAccount(bruto) {
  if (!bruto || typeof bruto !== 'object' || Array.isArray(bruto)) return null;
  const coins = Math.max(0, Math.min(1e12, Math.floor(Number(bruto.coins) || 0)));
  const lista = (v) => (Array.isArray(v) ? v.filter((x) => typeof x === 'string' && x.length <= 64).slice(0, COINS_MAX_ITEMS) : []);
  const l = bruto.ledger && typeof bruto.ledger === 'object' ? bruto.ledger : {};
  const janela = (j) => ({ windowStart: Math.max(0, Math.floor(Number(j && j.windowStart) || 0)), count: Math.max(0, Math.floor(Number(j && j.count) || 0)) });
  const requests = {};
  if (l.requests && typeof l.requests === 'object' && !Array.isArray(l.requests)) {
    for (const [k, v] of Object.entries(l.requests)) {
      if (!/^[A-Za-z0-9_-]{6,64}$/.test(k)) continue;
      requests[k] = {
        item: String((v && v.item) || '').slice(0, 64),
        tipo: String((v && v.tipo) || '').slice(0, 16),
        at: Math.max(0, Math.floor(Number(v && v.at) || 0)),
        coins: Math.max(0, Math.floor(Number(v && v.coins) || 0))
      };
    }
  }
  return {
    key: String(bruto.key || '').slice(0, 80),
    kind: bruto.kind === 'social' ? 'social' : 'offline',
    name: String(bruto.name || '').replace(/[\r\n\t]/g, ' ').slice(0, 32),
    coins,
    ownedCapes: lista(bruto.ownedCapes),
    ownedSeals: lista(bruto.ownedSeals),
    // Expiração das capas de PRÊMIO (TOP TEMPO, 30 dias): id -> timestamp ms.
    // SEM isso o sanitizador descartava o campo na leitura E na gravação, e a
    // capa de prêmio nunca expirava (bug pego pelo teste rc-teste-expiry.js).
    capeExpiry: (() => {
      const out = {};
      const e = bruto.capeExpiry;
      if (e && typeof e === 'object' && !Array.isArray(e)) {
        for (const [k, v] of Object.entries(e)) {
          if (!/^[a-z0-9_-]{1,64}$/i.test(String(k))) continue;
          const n = Math.floor(Number(v) || 0);
          if (n > 0) out[String(k)] = n;
        }
      }
      return out;
    })(),
    ledger: {
      lastEarnAt: Math.max(0, Math.floor(Number(l.lastEarnAt) || 0)),
      lastEarnEvent: String(l.lastEarnEvent || '').slice(0, 16),
      totalEarned: Math.max(0, Math.floor(Number(l.totalEarned) || 0)),
      earnCount: Math.max(0, Math.floor(Number(l.earnCount) || 0)),
      hour: janela(l.hour),
      day: janela(l.day),
      spent: Math.max(0, Math.floor(Number(l.spent) || 0)),
      items: Array.isArray(l.items) ? l.items.slice(-COINS_MAX_ITEMS).map((it) => ({
        item: String((it && it.item) || '').slice(0, 64),
        tipo: String((it && it.tipo) || '').slice(0, 16),
        price: Math.max(0, Math.floor(Number(it && it.price) || 0)),
        at: Math.max(0, Math.floor(Number(it && it.at) || 0))
      })) : [],
      requests,
      sources: lista(l.sources),
      anomalies: Array.isArray(l.anomalies) ? l.anomalies.slice(-20).map((a) => ({
        at: Math.max(0, Math.floor(Number(a && a.at) || 0)),
        reason: String((a && a.reason) || '').slice(0, 40),
        detail: String((a && a.detail) || '').slice(0, 80)
      })) : []
    },
    createdAt: Math.max(0, Math.floor(Number(bruto.createdAt) || 0)),
    updatedAt: Math.max(0, Math.floor(Number(bruto.updatedAt) || 0))
  };
}

function readCoins() {
  try {
    if (!fs.existsSync(COINS_FILE)) return coinsDefaultFile();
    const bruto = JSON.parse(fs.readFileSync(COINS_FILE, 'utf-8'));
    if (!bruto || typeof bruto !== 'object' || Array.isArray(bruto)) return coinsDefaultFile();
    const base = coinsDefaultFile();
    const accounts = {};
    const origem = bruto.accounts && typeof bruto.accounts === 'object' && !Array.isArray(bruto.accounts) ? bruto.accounts : {};
    for (const [chave, valor] of Object.entries(origem)) {
      if (!/^(social|offline):[A-Za-z0-9_.:-]{1,70}$/.test(String(chave))) continue;
      const acc = coinsSanitizeAccount(valor);
      if (!acc) continue;
      acc.key = String(chave);
      accounts[chave] = acc;
    }
    return Object.assign(base, {
      migratedFromLocalConfig: bruto.migratedFromLocalConfig === true,
      accounts
    });
  } catch (_) {
    return coinsDefaultFile(); // arquivo ausente/corrompido => recomeça vazio
  }
}

function writeCoins(dados) {
  try {
    if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
    // teto defensivo: mantém as contas mais recentes
    const chaves = Object.keys(dados.accounts || {});
    if (chaves.length > COINS_MAX_ACCOUNTS) {
      chaves
        .sort((a, b) => (dados.accounts[b].updatedAt || 0) - (dados.accounts[a].updatedAt || 0))
        .slice(COINS_MAX_ACCOUNTS)
        .forEach((k) => delete dados.accounts[k]);
    }
    dados.policy = coinsPolicy();
    dados.updatedAt = new Date().toISOString();
    const tempFile = COINS_FILE + '.tmp';
    fs.writeFileSync(tempFile, JSON.stringify(dados, null, 2), 'utf-8');
    fs.renameSync(tempFile, COINS_FILE); // troca atômica
    return true;
  } catch (_) {
    return false;
  }
}

// F09: campos de VALOR de economia no body do cliente sao SEMPRE ignorados (e
// registrados). O saldo/preco/posse vivem no servidor (data/coins.json + catalogo
// COIN_CAPE_PRICES/COIN_SEAL_PRICES); o cliente so escolhe o TIPO do evento de
// earn e o ITEM comprado. Editar o config.json do launcher nao credita nada.
const COINS_CLIENT_VALUE_FIELDS = ['amount', 'coins', 'price', 'balance', 'saldo', 'total', 'value', 'preco', 'coinsDelta', 'delta', 'grant'];
function coinsClientValueFields(body) {
  if (!body || typeof body !== 'object' || Array.isArray(body)) return [];
  return COINS_CLIENT_VALUE_FIELDS.filter((k) => Object.prototype.hasOwnProperty.call(body, k));
}
function coinsNoteIgnoredClientValues(req, body) {
  const campos = coinsClientValueFields(body);
  if (campos.length) {
    try { console.warn('[coins] valores de economia vindos do cliente IGNORADOS em ' + req.path + ': ' + campos.join(', ')); } catch (_) {}
  }
  return campos;
}

/** Identidade da conta: token social > conta offline/uuid (mesmo modelo do Top Tempo). */
function coinsIdentity(req) {
  try {
    const m = String(req.headers.authorization || '').match(/^Bearer\s+(.+)$/i);
    const token = m && m[1];
    if (token) {
      const u = social.findUserByToken(token);
      if (u && u.id) {
        const socialName = String(u.username || '').replace(/[\r\n\t]/g, ' ').slice(0, 32);
        try { trackDevice(req, socialName, String(u.uuid || u.id || '')); } catch (_) {}
        return {
          key: 'social:' + String(u.id).slice(0, 70),
          name: socialName,
          kind: 'social',
          device: String(req.headers['x-reality-device'] || '').slice(0, 64)
        };
      }
    }
  } catch (_) { /* sem social/token inválido: cai pro uuid */ }
  const bruto = String(req.headers['x-reality-uuid'] || (req.body && req.body.uuid) || '').trim();
  const name = String(req.headers['x-reality-name'] || (req.body && req.body.name) || '').replace(/[\r\n\t]/g, ' ').slice(0, 32);
  if (!/^[0-9a-fA-F-]{32,36}$/.test(bruto)) return null;
  const nome = /^[A-Za-z0-9_]{1,16}$/.test(name) ? name : '';
  try { trackDevice(req, nome, normalizeUuid(bruto)); } catch (_) {}
  return {
    key: 'offline:' + normalizeUuid(bruto),
    name: nome,
    kind: 'offline',
    device: String(req.headers['x-reality-device'] || '').slice(0, 64)
  };
}

function coinsNewLedger() {
  return {
    lastEarnAt: 0,
    lastEarnEvent: '',
    totalEarned: 0,
    earnCount: 0,
    hour: { windowStart: 0, count: 0 },
    day: { windowStart: 0, count: 0 },
    spent: 0,
    items: [],
    requests: {},
    sources: [],
    anomalies: []
  };
}

function coinsEnsureAccount(dados, ident) {
  let acc = dados.accounts[ident.key];
  if (!acc) {
    acc = {
      key: ident.key,
      kind: ident.kind,
      name: ident.name || '',
      coins: 0,
      ownedCapes: [],
      ownedSeals: [],
      ledger: coinsNewLedger(),
      createdAt: Date.now(),
      updatedAt: Date.now()
    };
    dados.accounts[ident.key] = acc;
  }
  if (ident.name) acc.name = ident.name;
  return acc;
}

/**
 * Ledger/anti-fraude: registra de onde veio o pedido (X-Reality-Device) e marca
 * anomalia quando uma conta JÁ usada aparece com um device novo (config.json
 * copiado de outra máquina, uuid forjado etc). NUNCA bloqueia o jogador legítimo.
 */
function coinsNoteSource(acc, ident) {
  const src = String(ident.device || '').slice(0, 64);
  if (!src) return;
  const ledger = acc.ledger;
  if (!Array.isArray(ledger.sources)) ledger.sources = [];
  if (!ledger.sources.includes(src)) {
    if (ledger.sources.length >= 1) {
      ledger.anomalies.push({ at: Date.now(), reason: 'device_novo', detail: src.slice(0, 32) });
      if (ledger.anomalies.length > 20) ledger.anomalies.shift();
    }
    ledger.sources.push(src);
    if (ledger.sources.length > 3) ledger.sources.shift();
  }
}

function coinsPublicState(acc, ident) {
  const now = Date.now();
  const ledger = acc.ledger;
  const proximo = Math.max(0, (ledger.lastEarnAt || 0) + COINS_EARN_INTERVAL_MS - now);
  return {
    ok: true,
    account: { kind: acc.kind, name: acc.name || (ident && ident.name) || '' },
    coins: Math.max(0, Math.floor(Number(acc.coins) || 0)),
    ownedCapes: capesVivasDaConta(acc),
    ownedSeals: Array.isArray(acc.ownedSeals) ? acc.ownedSeals.slice() : [],
    // Selos EXCLUSIVOS (só por código): catálogo próprio p/ UI (arte) + o que a
    // conta já possui. Fora de prices.seals de propósito (não estão à venda).
    exclusiveSeals: coinsExclusiveSeals(),
    ownedSealsExclusive: (Array.isArray(acc.ownedSeals) ? acc.ownedSeals : []).filter((id) => !!COIN_SEAL_EXCLUSIVE[id]),
    // Capas EXCLUSIVAS (só por código): catálogo próprio p/ UI, fora de
    // prices.capes de propósito (não estão à venda). A capa PRIVADA (hidden)
    // não entra no catálogo público — aparece só no ownedCapes de quem resgatou.
    exclusiveCapes: coinsExclusiveCapes(),
    ownedCapesExclusive: capesVivasDaConta(acc).filter((id) => !!COIN_CAPE_EXCLUSIVE[id]),
    earn: {
      lastEarnAt: ledger.lastEarnAt || 0,
      nextInMs: proximo,
      totalEarned: ledger.totalEarned || 0,
      earnCount: ledger.earnCount || 0,
      remainingHour: Math.max(0, COINS_EARN_MAX_PER_HOUR - ((ledger.hour && ledger.hour.count) || 0)),
      remainingDay: Math.max(0, COINS_EARN_MAX_PER_DAY - ((ledger.day && ledger.day.count) || 0))
    },
    policy: coinsPolicy(),
    prices: coinsCatalog(),
    serverTime: now
  };
}

/** Credita moedas de código de resgate (chamado pelo POST /api/redeem). */
function coinsCreditRedeem(ident, amount, code) {
  const premio = Math.max(0, Math.min(100000, Math.floor(Number(amount) || 0)));
  if (!ident || !premio) return Promise.resolve({ credited: 0 });
  return withCoinsLock(() => {
    const dados = readCoins();
    const acc = coinsEnsureAccount(dados, ident);
    coinsNoteSource(acc, ident);
    acc.coins = Math.max(0, Math.floor(Number(acc.coins) || 0)) + premio;
    acc.ledger.totalEarned = Math.max(0, Math.floor(Number(acc.ledger.totalEarned) || 0)) + premio;
    acc.ledger.lastEarnEvent = 'code:' + String(code || '').slice(0, 24);
    acc.ledger.earnCount = Math.max(0, Math.floor(Number(acc.ledger.earnCount) || 0)) + 1;
    acc.updatedAt = Date.now();
    writeCoins(dados);
    return { credited: premio, coins: acc.coins };
  });
}

/**
 * Concede uma CAPA EXCLUSIVA (de código) na CONTA (ownedCapes do
 * data/coins.json) — chamado pelo POST /api/redeem quando a entrada premiada
 * traz `capeId`. Idempotente (se a conta já tem a capa, already: true). NÃO
 * credita moeda: a recompensa do código é a POSSE. Sem identidade não concede
 * nada. Escrita atômica via writeCoins, na fila withCoinsLock.
 */
function coinsGrantCape(ident, capeId, code) {
  const id = String(capeId || '').trim();
  if (!ident || !ident.key || !/^[a-z0-9_]{3,40}$/.test(id)) {
    return Promise.resolve({ granted: false, already: false });
  }
  return withCoinsLock(() => {
    const dados = readCoins();
    const acc = coinsEnsureAccount(dados, ident);
    coinsNoteSource(acc, ident);
    if (!Array.isArray(acc.ownedCapes)) acc.ownedCapes = [];
    const ja = acc.ownedCapes.includes(id);
    if (!ja) {
      acc.ownedCapes.push(id);
      if (acc.ownedCapes.length > COINS_MAX_ITEMS) acc.ownedCapes.splice(0, acc.ownedCapes.length - COINS_MAX_ITEMS);
      acc.ledger.lastEarnEvent = 'code-cape:' + String(code || '').slice(0, 24);
      acc.updatedAt = Date.now();
      writeCoins(dados);
    }
    return { granted: !ja, already: ja, capeId: id, ownedCapes: acc.ownedCapes.slice() };
  });
}

/**
 * Concede um selo EXCLUSIVO na CONTA (ownedSeals do data/coins.json) — chamado
 * pelo POST /api/redeem quando o código premiado traz `seal`. Idempotente: se a
 * conta já tem o selo, não duplica (already: true). SEM identidade não concede
 * nada (o resgate de código de selo exige conta). Escrita atômica via
 * writeCoins; fila withCoinsLock (nada de corrida com earn/spend/redeem).
 */
function coinsGrantSeal(ident, sealId, code) {
  const id = String(sealId || '').trim().toLowerCase();
  if (!ident || !ident.key || !COIN_SEAL_EXCLUSIVE[id]) {
    return Promise.resolve({ granted: false, already: false });
  }
  return withCoinsLock(() => {
    const dados = readCoins();
    const acc = coinsEnsureAccount(dados, ident);
    coinsNoteSource(acc, ident);
    if (!Array.isArray(acc.ownedSeals)) acc.ownedSeals = [];
    if (!acc.ledger || typeof acc.ledger !== 'object') acc.ledger = coinsNewLedger();
    if (!Array.isArray(acc.ledger.items)) acc.ledger.items = [];
    const jaTinha = acc.ownedSeals.includes(id);
    if (!jaTinha) {
      acc.ownedSeals.push(id);
      if (acc.ownedSeals.length > COINS_MAX_ITEMS) acc.ownedSeals.splice(0, acc.ownedSeals.length - COINS_MAX_ITEMS);
      // Registro no ledger (price 0: selo de código NÃO é compra — não mexe em spent).
      acc.ledger.items.push({ item: id, tipo: 'seal', price: 0, at: Date.now() });
      if (acc.ledger.items.length > COINS_MAX_ITEMS) acc.ledger.items.splice(0, acc.ledger.items.length - COINS_MAX_ITEMS);
    }
    acc.updatedAt = Date.now();
    writeCoins(dados);
    return { granted: !jaTinha, already: jaTinha, seal: id, ownedSeals: acc.ownedSeals.slice() };
  });
}

// GET /api/coins — saldo + posse + catálogo da conta (token social ou uuid offline).
app.get('/api/coins', (req, res) => {
  try {
    res.setHeader('Cache-Control', 'no-store');
    if (!rateLimit(clientKey(req), 'coins-get', 120, 60000)) {
      return res.status(429).json({ ok: false, error: 'too_many_requests' });
    }
    const ident = coinsIdentity(req);
    if (!ident) return res.status(400).json({ ok: false, error: 'no_account' });
    // Lista negra: conta banida não lê creditos/prices nem materializa saldo.
    const banGet = banCheckRequest(req, ident);
    if (banGet) return res.status(403).json(banBlockBody(banGet));
    withCoinsLock(() => {
      const dados = readCoins();
      const acc = coinsEnsureAccount(dados, ident);
      coinsNoteSource(acc, ident);
      writeCoins(dados); // materializa a conta (zero) no arquivo
      return coinsPublicState(acc, ident);
    }).then((estado) => {
      try { res.json(estado); } catch (_) {}
    }).catch(() => {
      try { res.status(500).json({ ok: false, error: 'coins_read_failed' }); } catch (_) {}
    });
  } catch (e) {
    try { res.status(500).json({ ok: false, error: 'coins_read_failed' }); } catch (_) {}
  }
});

// POST /api/coins/earn — o launcher reporta o TICK (tipo do evento). O valor é
// SEMPRE o do servidor; o cooldown/teto é por conta (o cliente não escolhe nada).
app.post('/api/coins/earn', (req, res) => {
  try {
    const body = req.body || {};
    coinsNoteIgnoredClientValues(req, body); // F09: amount/coins/price do cliente nao valem nada
    const event = String(body.event || 'launcher').toLowerCase();
    if (!COINS_EARN_EVENTS.has(event)) {
      return res.status(400).json({ ok: false, error: 'invalid_event' });
    }
    if (!rateLimit(clientKey(req), 'coins-earn', COINS_EARN_MAX_PER_MIN, 60000)) {
      return res.status(429).json({ ok: false, error: 'too_many_requests' });
    }
    const ident = coinsIdentity(req);
    if (!ident) return res.status(400).json({ ok: false, error: 'no_account' });
    // Lista negra: conta banida não ganha moeda pelo tick.
    const banEarn = banCheckRequest(req, ident);
    if (banEarn) return res.status(403).json(banBlockBody(banEarn));
    withCoinsLock(() => {
      const dados = readCoins();
      const acc = coinsEnsureAccount(dados, ident);
      coinsNoteSource(acc, ident);
      const ledger = acc.ledger;
      const now = Date.now();
      const proximo = Math.max(0, (ledger.lastEarnAt || 0) + COINS_EARN_INTERVAL_MS - now);
      if (proximo > 0) {
        acc.updatedAt = now;
        writeCoins(dados);
        return { status: 429, body: { ok: false, error: 'too_soon', nextInMs: proximo, coins: Math.max(0, Math.floor(Number(acc.coins) || 0)) } };
      }
      // Janelas de teto (hora/dia) — o servidor é quem conta, nunca o cliente.
      if (!ledger.hour || now - (ledger.hour.windowStart || 0) >= 3600000) ledger.hour = { windowStart: now, count: 0 };
      if (!ledger.day || now - (ledger.day.windowStart || 0) >= 86400000) ledger.day = { windowStart: now, count: 0 };
      if (ledger.hour.count >= COINS_EARN_MAX_PER_HOUR) {
        return { status: 429, body: { ok: false, error: 'hour_cap', coins: Math.max(0, Math.floor(Number(acc.coins) || 0)) } };
      }
      if (ledger.day.count >= COINS_EARN_MAX_PER_DAY) {
        return { status: 429, body: { ok: false, error: 'day_cap', coins: Math.max(0, Math.floor(Number(acc.coins) || 0)) } };
      }
      acc.coins = Math.max(0, Math.floor(Number(acc.coins) || 0)) + COINS_EARN_AMOUNT;
      ledger.totalEarned = Math.max(0, Math.floor(Number(ledger.totalEarned) || 0)) + COINS_EARN_AMOUNT;
      ledger.earnCount = Math.max(0, Math.floor(Number(ledger.earnCount) || 0)) + 1;
      ledger.lastEarnAt = now;
      ledger.lastEarnEvent = event;
      ledger.hour.count += 1;
      ledger.day.count += 1;
      acc.updatedAt = now;
      writeCoins(dados);
      return {
        status: 200,
        body: {
          ok: true,
          credited: COINS_EARN_AMOUNT,
          event,
          coins: acc.coins,
          nextInMs: COINS_EARN_INTERVAL_MS,
          earn: {
            totalEarned: ledger.totalEarned,
            earnCount: ledger.earnCount,
            remainingHour: Math.max(0, COINS_EARN_MAX_PER_HOUR - ledger.hour.count),
            remainingDay: Math.max(0, COINS_EARN_MAX_PER_DAY - ledger.day.count)
          }
        }
      };
    }).then((out) => {
      try { res.status(out.status).json(out.body); } catch (_) {}
    }).catch(() => {
      try { res.status(500).json({ ok: false, error: 'coins_earn_failed' }); } catch (_) {}
    });
  } catch (e) {
    try { res.status(500).json({ ok: false, error: 'coins_earn_failed' }); } catch (_) {}
  }
});

// POST /api/coins/spend — compra validada AQUI: preço do catálogo do servidor,
// débito atômico, posse gravada, idempotente por requestId.
app.post('/api/coins/spend', (req, res) => {
  try {
    const body = req.body || {};
    coinsNoteIgnoredClientValues(req, body); // F09: price/coins/amount do cliente nao valem nada
    const item = String(body.item || '').trim().slice(0, 64);
    const tipo = String(body.tipo || '').trim().toLowerCase();
    const requestId = String(body.requestId || '').trim().slice(0, 64);
    if (tipo !== 'cape' && tipo !== 'seal') {
      return res.status(400).json({ ok: false, error: 'invalid_tipo' });
    }
    // Selo EXCLUSIVO de código (ex.: beta_test): NUNCA está à venda. A resposta é
    // explícita e nada é debitado (nem cai no 'unknown_item' genérico).
    if (tipo === 'seal' && COIN_SEAL_EXCLUSIVE[item]) {
      return res.status(400).json({
        ok: false,
        error: 'not_for_sale',
        item,
        tipo,
        message: 'Selo exclusivo de codigo: so sai por resgate.'
      });
    }
    // Capa EXCLUSIVA de código (ex.: capa_beta_test): NUNCA está à venda — a
    // resposta é explícita e nada é debitado. Vale também para a capa PRIVADA.
    if (tipo === 'cape' && COIN_CAPE_EXCLUSIVE[item]) {
      return res.status(400).json({
        ok: false,
        error: 'not_for_sale',
        item,
        tipo,
        message: 'Capa exclusiva de codigo: so sai por resgate.'
      });
    }
    const catalogo = tipo === 'cape' ? COIN_CAPE_PRICES : COIN_SEAL_PRICES;
    const price = catalogo[item];
    if (!Number.isFinite(price)) {
      return res.status(400).json({ ok: false, error: 'unknown_item' });
    }
    if (!rateLimit(clientKey(req), 'coins-spend', COINS_SPEND_MAX_PER_MIN, 60000)) {
      return res.status(429).json({ ok: false, error: 'too_many_requests' });
    }
    const ident = coinsIdentity(req);
    if (!ident) return res.status(400).json({ ok: false, error: 'no_account' });
    // Lista negra: conta banida não compra (nada de gastar saldo/ganhar posse).
    const banSpend = banCheckRequest(req, ident);
    if (banSpend) return res.status(403).json(banBlockBody(banSpend));
    withCoinsLock(() => {
      const dados = readCoins();
      const acc = coinsEnsureAccount(dados, ident);
      coinsNoteSource(acc, ident);
      const saldo = Math.max(0, Math.floor(Number(acc.coins) || 0));
      const posse = tipo === 'cape' ? acc.ownedCapes : acc.ownedSeals;
      const ledger = acc.ledger;
      // Idempotência: mesmo pedido repetido (retry/timeout) não debita de novo.
      if (/^[A-Za-z0-9_-]{6,64}$/.test(requestId) && ledger.requests && ledger.requests[requestId]) {
        const anterior = ledger.requests[requestId];
        return {
          status: 200,
          body: {
            ok: true,
            already: true,
            idempotent: true,
            item: anterior.item,
            tipo: anterior.tipo,
            coins: saldo,
            price: anterior.item === item ? price : undefined
          }
        };
      }
      if (posse.includes(item)) {
        return { status: 200, body: { ok: true, already: true, item, tipo, coins: saldo, price } };
      }
      if (saldo < price) {
        return { status: 200, body: { ok: false, error: 'not_enough', item, tipo, coins: saldo, need: price } };
      }
      acc.coins = saldo - price;
      posse.push(item);
      if (posse.length > COINS_MAX_ITEMS) posse.splice(0, posse.length - COINS_MAX_ITEMS);
      ledger.spent = Math.max(0, Math.floor(Number(ledger.spent) || 0)) + price;
      ledger.items.push({ item, tipo, price, at: Date.now() });
      if (ledger.items.length > COINS_MAX_ITEMS) ledger.items.splice(0, ledger.items.length - COINS_MAX_ITEMS);
      if (/^[A-Za-z0-9_-]{6,64}$/.test(requestId)) {
        if (!ledger.requests || typeof ledger.requests !== 'object') ledger.requests = {};
        ledger.requests[requestId] = { item, tipo, at: Date.now(), coins: acc.coins };
        const chaves = Object.keys(ledger.requests);
        if (chaves.length > COINS_MAX_REQUESTS) {
          chaves.sort((a, b) => (ledger.requests[a].at || 0) - (ledger.requests[b].at || 0));
          chaves.slice(0, chaves.length - COINS_MAX_REQUESTS).forEach((k) => delete ledger.requests[k]);
        }
      }
      acc.updatedAt = Date.now();
      writeCoins(dados);
      return {
        status: 200,
        body: {
          ok: true,
          item,
          tipo,
          price,
          spent: price,
          coins: acc.coins,
          ownedCapes: acc.ownedCapes.slice(),
          ownedSeals: acc.ownedSeals.slice(),
          spentTotal: ledger.spent
        }
      };
    }).then((out) => {
      try { res.status(out.status).json(out.body); } catch (_) {}
    }).catch(() => {
      try { res.status(500).json({ ok: false, error: 'coins_spend_failed' }); } catch (_) {}
    });
  } catch (e) {
    try { res.status(500).json({ ok: false, error: 'coins_spend_failed' }); } catch (_) {}
  }
});

// GET /api/coins/ledger — leitura para o DONO (mesma chave dos relatórios do Guard):
// o ledger por conta (último earn, total ganho, itens, anomalias) é o que denuncia
// config.json editado / uuid forjado. Sem chave configurada, fica desabilitado.
app.get('/api/coins/ledger', (req, res) => {
  try {
    if (GUARD_KEY_IS_DEFAULT) {
      return res.status(503).json({ ok: false, error: 'guard_admin_disabled_no_key' });
    }
    const key = String(req.query.key || req.headers['x-admin-key'] || '');
    if (key !== GUARD_ADMIN_KEY) return res.status(401).json({ ok: false, error: 'unauthorized' });
    const dados = readCoins();
    const contas = Object.values(dados.accounts || {})
      .sort((a, b) => (b.updatedAt || 0) - (a.updatedAt || 0))
      .slice(0, Math.min(200, Math.max(1, parseInt(req.query.limit || '50', 10) || 50)))
      .map((acc) => ({ key: acc.key, kind: acc.kind, name: acc.name, coins: acc.coins, ledger: acc.ledger, updatedAt: acc.updatedAt }));
    res.json({
      ok: true,
      total: Object.keys(dados.accounts || {}).length,
      migratedFromLocalConfig: dados.migratedFromLocalConfig === true,
      accounts: contas
    });
  } catch (e) {
    try { res.status(500).json({ ok: false, error: 'coins_ledger_failed' }); } catch (_) {}
  }
});

app.listen(PORT, () => {
  ensureData();
  social.ensure();
  writeCoins(readCoins()); // cria/valida data/coins.json (economia server-authoritative)
  // SEMENTE IDEMPOTENTE dos 10 códigos do selo 'beta_test' (BTSRLY*): cria só os
  // que faltam no manifest.codes — NUNCA sobrescreve (código já resgatado
  // continua resgatado). Falha aqui não derruba o boot.
  seedBetaTestCodes()
    .then((r) => {
      if (r && r.created && r.created.length) console.log('[seals] codigos BTSRLY criados no manifesto: ' + r.created.join(', '));
    })
    .catch((e) => { console.warn('[seals] seed BTSRLY falhou: ' + ((e && e.message) || e)); });
  try { readBans(); } catch (_) {} // cria/valida data/bans.json (lista negra)
  try {
    const wurl = guardWebhookUrl();
    console.log('[guard] webhook ' + (wurl ? ('configurado (' + guardWebhookHost(wurl) + ')') : 'nao configurado (GUARD_WEBHOOK_URL ou data/guard-webhook.json)'));
  } catch (_) {}
  console.log(`[Reality Backend] http://0.0.0.0:${PORT}`);
  console.log(`[Reality Backend] Social: /api/social/*`);
  console.log(`[Reality Backend] Admin token: ${ADMIN_TOKEN === 'troque-este-token' ? '(PADRÃO — mude ADMIN_TOKEN!)' : '(custom)'}`);
});
