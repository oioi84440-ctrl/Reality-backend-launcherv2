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
  fs.writeFileSync(PRESENCE_FILE, JSON.stringify(data, null, 2), 'utf8');
}

function prune(data) {
  const now = Date.now();
  for (const [id, p] of Object.entries(data.players || {})) {
    if (!p || !p.updatedAt || now - p.updatedAt > TTL_MS) delete data.players[id];
  }
  return data;
}

function normalizeUuid(uuid) {
  return String(uuid || '').toLowerCase().replace(/-/g, '');
}

/** POST body: { uuid, username, capeId?, launcher: true } */
function heartbeat(body) {
  const uuid = normalizeUuid(body && body.uuid);
  if (!uuid || uuid.length < 32) return { ok: false, error: 'uuid_required' };
  const data = prune(load());
  if (!data.players) data.players = {};
  const prev = data.players[uuid] || {};
  data.players[uuid] = {
    uuid: String(body.uuid).toLowerCase(),
    username: String(body.username || prev.username || '').slice(0, 32),
    capeId: body.capeId != null ? String(body.capeId).slice(0, 64) : (prev.capeId || null),
    launcher: true,
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
