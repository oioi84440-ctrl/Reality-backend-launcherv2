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

function clientKey(req) {
  return String(req.headers['x-forwarded-for'] || req.socket.remoteAddress || 'unknown')
    .split(',')[0].trim().slice(0, 80);
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
const PRESENCE_TTL_MS = 45 * 1000;

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
  const name = String((req.body && req.body.name) || '').trim().slice(0, 32);
  if (!uuid || !/^[0-9a-fA-F-]{32,36}$/.test(uuid)) {
    return res.status(400).json({ error: 'invalid_uuid' });
  }
  onlineRealityUsers.set(uuid.toLowerCase(), { name, lastSeen: Date.now() });
  res.json({ ok: true });
});

app.get('/api/presence/online', (_req, res) => {
  const now = Date.now();
  const list = [];
  for (const [uuid, info] of onlineRealityUsers.entries()) {
    if (now - info.lastSeen <= PRESENCE_TTL_MS) {
      list.push({ uuid, name: info.name });
    } else {
      onlineRealityUsers.delete(uuid); // limpa quem expirou, de brinde
    }
  }
  res.json({ users: list });
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

app.get('/api/creators', (_req, res) => {
  try {
    const m = readManifest();
    res.json({ creators: m.creators || [] });
  } catch (e) {
    res.status(500).json({ error: 'creators_failed' });
  }
});

app.post('/api/redeem', async (req, res) => {
  try {
    if (isRateLimited(req)) return res.status(429).json({ error: 'too_many_attempts' });
    const code = String(req.body?.code || '').trim().toUpperCase().slice(0, 64);
    const username = String(req.body?.username || '').trim().slice(0, 40);
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
      const redeemer = username ? hashRedeemer(username) : null;
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

app.listen(PORT, () => {
  ensureData();
  social.ensure();
  console.log(`[Reality Backend] http://0.0.0.0:${PORT}`);
  console.log(`[Reality Backend] Social: /api/social/*`);
  console.log(`[Reality Backend] Admin token: ${ADMIN_TOKEN === 'troque-este-token' ? '(PADRÃO — mude ADMIN_TOKEN!)' : '(custom)'}`);
});
