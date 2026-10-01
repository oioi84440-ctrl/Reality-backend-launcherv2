/**
 * Presença Reality + capas compartilhadas entre jogadores.
 * Quem usa o launcher manda heartbeat; outros clients consultam e veem capa + marca no TAB.
 */
const fs = require('fs');
const path = require('path');

const PRESENCE_FILE = path.join(__dirname, 'data', 'presence.json');
const TTL_MS = 15 * 60 * 1000; // 15 min sem heartbeat = offline

function load() {
  try {
    return JSON.parse(fs.readFileSync(PRESENCE_FILE, 'utf8'));
  } catch (_) {
    return { players: {} };
  }
}

function save(data) {
  const dir = path.dirname(PRESENCE_FILE);
  if (!fs.existsSync(dir)) fs.mkdirSync(dir, { recursive: true });
  // L5: troca atomica (tmp + rename) — antes o writeFileSync direto truncava o
  // arquivo se o processo morresse no meio e o load() devolvia { players: {} }.
  const tmp = PRESENCE_FILE + '.tmp';
  fs.writeFileSync(tmp, JSON.stringify(data, null, 2), 'utf8');
  fs.renameSync(tmp, PRESENCE_FILE);
}

function prune(data) {
  const now = Date.now();
  for (const [id, p] of Object.entries(data.players || {})) {
    if (!p || !p.updatedAt || now - p.updatedAt > TTL_MS) delete data.players[id];
  }
  return data;
}

function normalizeUuid(uuid) {
  const h = String(uuid || '').toLowerCase().replace(/[^0-9a-f]/g, '');
  if (h.length !== 32) return String(uuid || '').toLowerCase();
  return h.slice(0, 8) + '-' + h.slice(8, 12) + '-' + h.slice(12, 16) + '-' + h.slice(16, 20) + '-' + h.slice(20);
}

/**
 * POST body: { uuid, username, capeId?, launcher: true, verified? }
 * F07: `verified` (heartbeat autenticado por token social ou HMAC) e decidido no
 * server.js e NUNCA rebaixado aqui — uma vez verificado, o dono continua dono ate
 * a entrada expirar. Tambem nao aceitamos nome novo para entrada ja verificada
 * vinda de heartbeat anonimo (o server.js ja barra antes; aqui e defesa dupla).
 */
function heartbeat(body) {
  const uuid = normalizeUuid(body && body.uuid);
  if (!/^[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}$/.test(uuid)) {
    return { ok: false, error: 'uuid_required' }; // L5: formato canonico, nao ">=32 chars"
  }
  const data = prune(load());
  if (!data.players) data.players = {};
  const prev = data.players[uuid] || {};
  const verified = body && body.verified === true ? true : prev.verified === true;
  const nomeNovo = body && body.username ? String(body.username).slice(0, 32) : '';
  data.players[uuid] = {
    uuid,
    username: verified ? (nomeNovo || prev.username || '') : (prev.verified ? (prev.username || '') : (nomeNovo || prev.username || '')),
    capeId: body.capeId != null ? String(body.capeId).slice(0, 64) : (prev.capeId || null),
    launcher: true,
    verified,
    updatedAt: Date.now()
  };
  save(data);
  return { ok: true, player: data.players[uuid] };
}

/** GET ?uuids=a,b,c  or all active */
function query(uuids) {
  const data = prune(load());
  const players = data.players || {};
  if (!uuids || !uuids.length) {
    return { ok: true, players: Object.values(players) };
  }
  const set = new Set(uuids.map(normalizeUuid));
  const out = [];
  for (const [id, p] of Object.entries(players)) {
    if (set.has(id) || set.has(normalizeUuid(p.uuid))) out.push(p);
  }
  return { ok: true, players: out };
}

function getCapeId(uuid) {
  const data = prune(load());
  const p = data.players[normalizeUuid(uuid)];
  return p && p.capeId ? p.capeId : null;
}

module.exports = { heartbeat, query, getCapeId, prune, load };
