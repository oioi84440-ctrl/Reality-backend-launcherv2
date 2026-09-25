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
          // Recompensa de moedas (opcional). Quem aplica e o launcher; limite defensivo aqui.
          coins: Math.max(0, Math.min(100000, Math.floor(Number(source.coins) || 0))),
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
//   POST /api/ranking/time  { uuid, name, ms }  -> acumula o tempo do jogador
//   GET  /api/ranking/time?limit=20             -> ranking (pos, name, ms)
// Dados: <data>/ranking-time.json = { "<uuid>": { name, ms, updatedAt } }
// O launcher reporta INCREMENTOS (a cada ~5 min e na saída); o total por jogador
// é o acumulado. Arquivo ausente/corrompido => recomeça vazio. Nunca derruba o servidor.
const RANKING_TIME_FILE = path.join(DATA_DIR, 'ranking-time.json');
const RANKING_TIME_MAX_REPORT_MS = 24 * 60 * 60 * 1000; // limite por reporte (não inflar)
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
    if (!Number.isFinite(ms) || !Number.isInteger(ms) || ms <= 0 || ms > RANKING_TIME_MAX_REPORT_MS) {
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
      let total = Math.floor(Number(prev.ms) || 0) + ms;
      if (!Number.isFinite(total) || total < 0) total = ms;
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

app.listen(PORT, () => {
  ensureData();
  social.ensure();
  console.log(`[Reality Backend] http://0.0.0.0:${PORT}`);
  console.log(`[Reality Backend] Social: /api/social/*`);
  console.log(`[Reality Backend] Admin token: ${ADMIN_TOKEN === 'troque-este-token' ? '(PADRÃO — mude ADMIN_TOKEN!)' : '(custom)'}`);
});
