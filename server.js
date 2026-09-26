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
 */

const fs = require('fs');
const path = require('path');
const express = require('express');
const presence = require('./presence');
const cors = require('cors');

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
  // SEGURANCA: o cliente nao escolhe a propria chave do rate limit (X-Forwarded-For e forjavel).
  const ip = req.socket.remoteAddress || '';
  if (!rateLimit(ip, 'global', 120, 60000)) {
    return res.status(429).json({ ok: false, error: 'Too many requests' });
  }
  next();
});


function clientKey(req) {
  // SEGURANCA: nunca usar X-Forwarded-For aqui (o cliente forja e cai em bucket novo).
  return String(req.socket.remoteAddress || 'unknown').slice(0, 80);
}

function isRateLimited(req) {
  const key = clientKey(req);
  const now = Date.now();
  const recent = (redeemAttempts.get(key) || []).filter((time) => now - time < 60_000);
  recent.push(now);
  redeemAttempts.set(key, recent);
  return recent.length > 20;
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

app.post('/api/presence/heartbeat', (req, res) => {
  const uuid = String((req.body && req.body.uuid) || '').trim();
  const name = String((req.body && (req.body.name || req.body.username)) || '').trim().slice(0, 32);
  const capeId = req.body && req.body.capeId != null ? String(req.body.capeId).slice(0, 64) : null;
  if (!uuid || !/^[0-9a-fA-F-]{32,36}$/.test(uuid)) {
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
  const prev = onlineRealityUsers.get(key) || {};
  onlineRealityUsers.set(key, {
    name: name || prev.name || '',
    capeId: capeId !== null ? capeId : (prev.capeId || null),
    lastSeen: Date.now()
  });
  // Persistência em disco (capas entre reinícios curtos do backend)
  try {
    if (typeof presence !== 'undefined' && presence.heartbeat) {
      presence.heartbeat({ uuid: key, username: name, capeId: capeId !== null ? capeId : prev.capeId });
    }
  } catch (_) {}
  res.json({ ok: true });
});

app.get('/api/presence/online', (_req, res) => {
  const now = Date.now();
  const list = [];
  for (const [uuid, info] of onlineRealityUsers.entries()) {
    if (now - info.lastSeen <= PRESENCE_TTL_MS) {
      list.push({ uuid, name: info.name, capeId: info.capeId || null, launcher: true });
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
      list.push({ uuid, name: info.name, capeId: info.capeId || null, launcher: true });
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

/** Feed de update no formato do updateChecker */
app.get('/api/update', (_req, res) => {
  try {
    const m = readManifest();
    res.json({
      version: m.launcher?.latestVersion || '1.0.0',
      url: m.launcher?.downloadUrl || '',
      notes: m.launcher?.notes || '',
      sha256: m.launcher?.sha256 || '',
      size: Number(m.launcher?.size || 0) || 0,
      mandatory: Boolean(m.launcher?.mandatory),
      platforms: m.launcher?.platforms || {}
    });
  } catch (e) {
    res.status(500).json({ error: 'update_read_failed' });
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
  const ipR = req.headers['x-forwarded-for'] || req.socket.remoteAddress || '';
  if (!rateLimit(ipR, 'redeem', 10, 60000)) {
    return res.status(429).json({ ok: false, error: 'Too many redeem attempts' });
  }

  try {
    if (isRateLimited(req)) return res.status(429).json({ error: 'too_many_attempts' });
    const code = String(req.body?.code || '').trim().toUpperCase().slice(0, 64);
    const username = String(req.body?.username || '').trim().slice(0, 40);
  const socialToken = String((req.headers.authorization || '').replace(/^Bearer /i, '') || '').slice(0, 80);
    if (!code) return res.status(400).json({ error: 'missing_code' });
    // Identidade da conta (token social ou conta offline/uuid) — usada para creditar
    // a recompensa de moedas do código AQUI no servidor, nunca no config do jogador.
    const coinsIdentRedeem = coinsIdentity(req);

    const result = await withRedeemLock(async () => {
      const m = readManifest();
      const entry = (m.codes || {})[code];
      if (!entry) return { status: 404, body: { error: 'invalid_code' } };
      if (entry.usesLeft != null && Number(entry.usesLeft) <= 0) {
        return { status: 410, body: { error: 'code_exhausted' } };
      }
      if (entry.expiresAt && (!Number.isFinite(Date.parse(entry.expiresAt)) || Date.now() > Date.parse(entry.expiresAt))) {
        return { status: 410, body: { error: 'code_expired' } };
      }

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
      if (redeemer && redeemedBy.includes(redeemer)) {
        return { status: 409, body: { error: 'code_already_redeemed' } };
      }

      if (entry.usesLeft != null) entry.usesLeft = Math.max(0, Number(entry.usesLeft) - 1);
      if (redeemer) {
        // Limita o histórico para não deixar o manifesto crescer sem controle.
        entry.redeemedBy = [...redeemedBy, redeemer].slice(-5000);
      }
      if (redeemer || entry.usesLeft != null) {
        m.codes[code] = entry;
        persistManifest(m);
      }

      const source = entry.reward && typeof entry.reward === 'object' ? entry.reward : entry;
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

// ---------- Social (amigos, pedidos, chat, presença) ----------
const { createSocial } = require('./social');
const social = createSocial(DATA_DIR);
social.mount(app);


// ---------- Reality Guard reports (donos) ----------
const guardReports = [];
const GUARD_ADMIN_KEY = process.env.GUARD_ADMIN_KEY || process.env.ADMIN_KEY || '';
const GUARD_KEY_IS_DEFAULT = !GUARD_ADMIN_KEY;
if (GUARD_KEY_IS_DEFAULT) console.warn('[guard] GUARD_ADMIN_KEY nao definida - leitura de relatorios desabilitada');
const MAX_GUARD_REPORTS = 500;

app.post('/api/guard/report', (req, res) => {
  try {
    const body = req.body || {};
    const report = {
      id: 'g_' + Date.now().toString(36) + '_' + Math.random().toString(36).slice(2, 7),
      at: Date.now(),
      username: String(body.username || body.name || 'unknown').replace(/[\r\n\t]/g, ' ').slice(0, 32),
      uuid: String(body.uuid || '').slice(0, 64),
      hits: (Array.isArray(body.hits) ? body.hits.slice(0, 40) : []).map((h) => {
        try { return JSON.stringify(h).slice(0, 400); } catch (_) { return 'invalid_hit'; }
      }),
      version: String(body.version || '').slice(0, 32),
      reason: String(body.reason || 'guard').slice(0, 64)
    };
    guardReports.unshift(report);
    if (guardReports.length > MAX_GUARD_REPORTS) guardReports.length = MAX_GUARD_REPORTS;
    console.log('[guard]', report.username, report.hits.length, 'hit(s)');
    res.json({ ok: true, id: report.id });
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


// ---------- Top Tempo (ranking global de tempo de uso) — aditivo ----------
// Endpoints NOVOS (nenhuma rota existente foi alterada):
//   POST /api/ranking/time  { uuid, name, ms }  -> TOTAL acumulado do jogador
//   GET  /api/ranking/time?limit=20             -> ranking (pos, name, ms, updatedAt)
// Dados: <data>/ranking-time.json = { "<uuid>": { name, ms, updatedAt } }
// O launcher reporta o TOTAL de tempo de launcher aberto (NÃO incrementos): a cada
// ~90s, logo após o boot e na saída. O valor guardado é max(anterior, ms) — um
// reporte perdido (offline/429/troca de conta) nunca mais atrasa o placar, o
// próximo reporte reenvia o total. Trava anti-inflação: um reporte sobe no máximo
// 24h acima do valor anterior e o valor NUNCA diminui; updatedAt = agora a cada
// reporte aceito (mantém a lista "viva" para todos os clientes). Arquivo
// ausente/corrompido => recomeça vazio. Nunca derruba o servidor.
const RANKING_TIME_FILE = path.join(DATA_DIR, 'ranking-time.json');
const RANKING_TIME_MAX_GROWTH_MS = 24 * 60 * 60 * 1000; // teto de crescimento por reporte
const RANKING_TIME_MAX_TOTAL_MS = 100 * 365 * 24 * 60 * 60 * 1000; // sanidade do payload (100 anos)
const RANKING_TIME_WINDOW_MS = 60 * 1000;               // 1 reporte por IP a cada ~60s
const RANKING_TIME_MAX_ENTRIES = 5000;                  // teto defensivo do arquivo
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
        // padrão (arquivo editado na mão / corrompido) é descartada.
        if (!/^[0-9a-fA-F-]{32,36}$/.test(String(uuid))) continue;
        const ms = Math.floor(Number(info.ms));
        if (!Number.isFinite(ms) || ms <= 0) continue;
        const name = String(info.name || '').trim();
        if (!/^[A-Za-z0-9_]{1,16}$/.test(name)) continue;
        limpo[String(uuid)] = {
          name,
          ms,
          updatedAt: Math.max(0, Math.floor(Number(info.updatedAt) || 0))
        };
      } catch (_) { /* entrada inválida: ignora */ }
    }
    return limpo;
  } catch (_) {
    return {}; // arquivo ausente/corrompido => recomeça vazio
  }
}

function writeRankingTime(dados) {
  try {
    if (!fs.existsSync(DATA_DIR)) fs.mkdirSync(DATA_DIR, { recursive: true });
    const tempFile = `${RANKING_TIME_FILE}.tmp`;
    fs.writeFileSync(tempFile, JSON.stringify(dados, null, 2), 'utf-8');
    fs.renameSync(tempFile, RANKING_TIME_FILE); // troca atômica (igual ao manifesto)
    return true;
  } catch (_) {
    return false;
  }
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
    // ms = TOTAL acumulado (pode passar de 24h: é o tempo de uso do jogador).
    // Aqui só um teto de sanidade do payload — a trava anti-inflação é aplicada
    // abaixo, contra o valor já guardado.
    if (!Number.isFinite(ms) || !Number.isInteger(ms) || ms <= 0 || ms > RANKING_TIME_MAX_TOTAL_MS) {
      return res.status(400).json({ ok: false, error: 'invalid_ms' });
    }
    // SEGURANCA: rate limit por IP REAL (clientKey — X-Forwarded-For é forjável):
    // no máximo 1 reporte a cada ~60s por IP.
    if (!rateLimit(clientKey(req), 'ranking-time', 1, RANKING_TIME_WINDOW_MS)) {
      return res.status(429).json({ ok: false, error: 'too_many_reports' });
    }
    const key = normalizeUuid(uuid);
    withRankingTimeLock(() => {
      const dados = readRankingTime();
      const prev = dados[key] || { name: '', ms: 0 };
      const anterior = Math.max(0, Math.floor(Number(prev.ms) || 0));
      // TOTAL ACUMULADO: guarda o MAIOR valor. Nunca soma (um incremento perdido
      // não atrasa mais o placar) e nunca diminui (reporte atrasado/menor é
      // ignorado no valor, mas renova o updatedAt).
      let total = Math.max(anterior, Math.floor(ms));
      // Trava anti-inflação: um único reporte não sobe mais de 24h acima do anterior.
      if (total > anterior + RANKING_TIME_MAX_GROWTH_MS) total = anterior + RANKING_TIME_MAX_GROWTH_MS;
      dados[key] = { name, ms: total, updatedAt: Date.now() };
      const chaves = Object.keys(dados);
      if (chaves.length > RANKING_TIME_MAX_ENTRIES) {
        // Teto defensivo: mantém só os maiores tempos.
        const maiores = chaves.sort((a, b) => dados[b].ms - dados[a].ms).slice(0, RANKING_TIME_MAX_ENTRIES);
        const reduzido = {};
        for (const k of maiores) reduzido[k] = dados[k];
        writeRankingTime(reduzido);
      } else {
        writeRankingTime(dados);
      }
      return total;
    }).then((total) => {
      try { res.json({ ok: true, ms: total }); } catch (_) {}
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
      .map(([uuid, info]) => ({ name: info.name, ms: info.ms, updatedAt: info.updatedAt || 0 }))
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
const COIN_CAPE_PRICES = {
  capa_montanha: 30,
  reality_bolt: 50,
  capa_copa_noruega: 250,
  capa_copa_brasil: 250,
  capa_copa_franca: 250,
  capa_copa_argentina: 250,
  capa_copa_espanha: 250,
  capa_copa_portugal: 250,
  capa_copa_italia: 250
};
// 120 selos do mercado (ids/preços idênticos ao catálogo embutido do launcher).
const COIN_SEAL_PRICES = {"seal_001":25,"seal_002":42,"seal_003":59,"seal_004":40,"seal_005":57,"seal_006":38,"seal_007":70,"seal_008":87,"seal_009":104,"seal_010":192,"seal_011":209,"seal_012":135,"seal_013":303,"seal_014":671,"seal_015":47,"seal_016":28,"seal_017":45,"seal_018":26,"seal_019":43,"seal_020":60,"seal_021":104,"seal_022":70,"seal_023":87,"seal_024":104,"seal_025":174,"seal_026":191,"seal_027":390,"seal_028":256,"seal_029":875,"seal_030":50,"seal_031":31,"seal_032":48,"seal_033":29,"seal_034":46,"seal_035":87,"seal_036":104,"seal_037":70,"seal_038":87,"seal_039":139,"seal_040":156,"seal_041":326,"seal_042":343,"seal_043":662,"seal_044":36,"seal_045":53,"seal_046":34,"seal_047":51,"seal_048":32,"seal_049":49,"seal_050":87,"seal_051":104,"seal_052":70,"seal_053":195,"seal_054":212,"seal_055":138,"seal_056":279,"seal_057":649,"seal_058":58,"seal_059":39,"seal_060":56,"seal_061":37,"seal_062":54,"seal_063":35,"seal_064":70,"seal_065":87,"seal_066":104,"seal_067":160,"seal_068":177,"seal_069":194,"seal_070":366,"seal_071":636,"seal_072":44,"seal_073":25,"seal_074":42,"seal_075":59,"seal_076":40,"seal_077":57,"seal_078":104,"seal_079":70,"seal_080":87,"seal_081":104,"seal_082":142,"seal_083":159,"seal_084":302,"seal_085":319,"seal_086":1042,"seal_087":47,"seal_088":28,"seal_089":45,"seal_090":26,"seal_091":43,"seal_092":87,"seal_093":104,"seal_094":70,"seal_095":87,"seal_096":198,"seal_097":215,"seal_098":141,"seal_099":255,"seal_100":627,"seal_101":33,"seal_102":50,"seal_103":31,"seal_104":48,"seal_105":29,"seal_106":46,"seal_107":87,"seal_108":104,"seal_109":70,"seal_110":163,"seal_111":180,"seal_112":197,"seal_113":342,"seal_114":614,"seal_115":55,"seal_116":36,"seal_117":53,"seal_118":34,"seal_119":51,"seal_120":32};

function coinsCatalog() {
  return { capes: Object.assign({}, COIN_CAPE_PRICES), seals: Object.assign({}, COIN_SEAL_PRICES) };
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

/** Identidade da conta: token social > conta offline/uuid (mesmo modelo do Top Tempo). */
function coinsIdentity(req) {
  try {
    const m = String(req.headers.authorization || '').match(/^Bearer\s+(.+)$/i);
    const token = m && m[1];
    if (token) {
      const u = social.findUserByToken(token);
      if (u && u.id) {
        return {
          key: 'social:' + String(u.id).slice(0, 70),
          name: String(u.username || '').replace(/[\r\n\t]/g, ' ').slice(0, 32),
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
    ownedCapes: Array.isArray(acc.ownedCapes) ? acc.ownedCapes.slice() : [],
    ownedSeals: Array.isArray(acc.ownedSeals) ? acc.ownedSeals.slice() : [],
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

// GET /api/coins — saldo + posse + catálogo da conta (token social ou uuid offline).
app.get('/api/coins', (req, res) => {
  try {
    res.setHeader('Cache-Control', 'no-store');
    if (!rateLimit(clientKey(req), 'coins-get', 120, 60000)) {
      return res.status(429).json({ ok: false, error: 'too_many_requests' });
    }
    const ident = coinsIdentity(req);
    if (!ident) return res.status(400).json({ ok: false, error: 'no_account' });
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
    const event = String(body.event || 'launcher').toLowerCase();
    if (!COINS_EARN_EVENTS.has(event)) {
      return res.status(400).json({ ok: false, error: 'invalid_event' });
    }
    if (!rateLimit(clientKey(req), 'coins-earn', COINS_EARN_MAX_PER_MIN, 60000)) {
      return res.status(429).json({ ok: false, error: 'too_many_requests' });
    }
    const ident = coinsIdentity(req);
    if (!ident) return res.status(400).json({ ok: false, error: 'no_account' });
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
    const item = String(body.item || '').trim().slice(0, 64);
    const tipo = String(body.tipo || '').trim().toLowerCase();
    const requestId = String(body.requestId || '').trim().slice(0, 64);
    if (tipo !== 'cape' && tipo !== 'seal') {
      return res.status(400).json({ ok: false, error: 'invalid_tipo' });
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
  console.log(`[Reality Backend] http://0.0.0.0:${PORT}`);
  console.log(`[Reality Backend] Social: /api/social/*`);
  console.log(`[Reality Backend] Admin token: ${ADMIN_TOKEN === 'troque-este-token' ? '(PADRÃO — mude ADMIN_TOKEN!)' : '(custom)'}`);
});
