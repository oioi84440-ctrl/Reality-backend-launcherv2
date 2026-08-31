/**
 * Reality Client — Social (estilo Feather)
 * Amigos, pedidos, presença online e mensagens diretas.
 * Persistência em JSON local (adequado a volume baixo; troque por DB se escalar).
 */

const fs = require('fs');
const path = require('path');
const crypto = require('crypto');

const ONLINE_MS = 90_000; // 90s sem heartbeat = offline
const MAX_MSG_LEN = 500;
const MAX_FRIENDS = 200;
const MAX_PENDING = 50;

function createSocial(dataDir) {
  const SOCIAL_DIR = path.join(dataDir, 'social');
  const USERS_FILE = path.join(SOCIAL_DIR, 'users.json');
  const FRIENDS_FILE = path.join(SOCIAL_DIR, 'friends.json');
  const REQUESTS_FILE = path.join(SOCIAL_DIR, 'requests.json');
  const MESSAGES_FILE = path.join(SOCIAL_DIR, 'messages.json');

  function ensure() {
    if (!fs.existsSync(SOCIAL_DIR)) fs.mkdirSync(SOCIAL_DIR, { recursive: true });
    for (const [file, def] of [
      [USERS_FILE, {}],
      [FRIENDS_FILE, {}],
      [REQUESTS_FILE, []],
      [MESSAGES_FILE, {}]
    ]) {
      if (!fs.existsSync(file)) fs.writeFileSync(file, JSON.stringify(def, null, 2));
    }
  }

  function readJson(file, fallback) {
    try {
      return JSON.parse(fs.readFileSync(file, 'utf-8'));
    } catch (_) {
      return fallback;
    }
  }

  function writeJson(file, data) {
    const tmp = file + '.tmp';
    fs.writeFileSync(tmp, JSON.stringify(data, null, 2), 'utf-8');
    fs.renameSync(tmp, file);
  }

  function normName(name) {
    return String(name || '').trim().toLowerCase();
  }

  function validUsername(name) {
    return /^[A-Za-z0-9_]{3,16}$/.test(String(name || '').trim());
  }

  function newId(prefix) {
    return prefix + '_' + crypto.randomBytes(8).toString('hex');
  }

  function newToken() {
    return crypto.randomBytes(24).toString('hex');
  }

  function publicUser(u, now = Date.now()) {
    if (!u) return null;
    const online = u.lastSeen && now - u.lastSeen < ONLINE_MS;
    return {
      id: u.id,
      username: u.username,
      displayName: u.displayName || u.username,
      status: online ? (u.status || 'online') : 'offline',
      lastSeen: u.lastSeen || null,
      online: !!online
    };
  }

  function findUserByToken(token) {
    ensure();
    const users = readJson(USERS_FILE, {});
    const t = String(token || '');
    for (const u of Object.values(users)) {
      if (u.token === t) return u;
    }
    return null;
  }

  function findUserByName(username) {
    ensure();
    const users = readJson(USERS_FILE, {});
    const key = normName(username);
    return Object.values(users).find((u) => normName(u.username) === key) || null;
  }

  function findUserById(id) {
    ensure();
    const users = readJson(USERS_FILE, {});
    return users[id] || null;
  }

  function saveUser(u) {
    const users = readJson(USERS_FILE, {});
    users[u.id] = u;
    writeJson(USERS_FILE, users);
  }

  /** Login/registro automático pelo nick do launcher. */
  function loginOrRegister({ username, displayName }) {
    ensure();
    if (!validUsername(username)) {
      const err = new Error('invalid_username');
      err.status = 400;
      throw err;
    }
    let user = findUserByName(username);
    if (!user) {
      user = {
        id: newId('u'),
        username: String(username).trim(),
        displayName: (displayName || username).trim().slice(0, 24),
        token: newToken(),
        status: 'online',
        lastSeen: Date.now(),
        createdAt: new Date().toISOString()
      };
      saveUser(user);
    } else {
      user.token = newToken();
      user.lastSeen = Date.now();
      user.status = 'online';
      user.placeholder = false;
      if (displayName) user.displayName = String(displayName).trim().slice(0, 24);
      saveUser(user);
    }
    return {
      token: user.token,
      user: publicUser(user)
    };
  }

  function heartbeat(token, status) {
    const user = findUserByToken(token);
    if (!user) {
      const err = new Error('unauthorized');
      err.status = 401;
      throw err;
    }
    user.lastSeen = Date.now();
    if (status && ['online', 'away', 'dnd'].includes(status)) user.status = status;
    else user.status = 'online';
    saveUser(user);
    return { ok: true, user: publicUser(user) };
  }

  function getFriends(token) {
    const me = findUserByToken(token);
    if (!me) {
      const err = new Error('unauthorized');
      err.status = 401;
      throw err;
    }
    ensure();
    const graph = readJson(FRIENDS_FILE, {});
    const ids = graph[me.id] || [];
    const now = Date.now();
    return ids
      .map((id) => publicUser(findUserById(id), now))
      .filter(Boolean)
      .sort((a, b) => Number(b.online) - Number(a.online) || a.username.localeCompare(b.username));
  }

  function getRequests(token) {
    const me = findUserByToken(token);
    if (!me) {
      const err = new Error('unauthorized');
      err.status = 401;
      throw err;
    }
    ensure();
    const reqs = readJson(REQUESTS_FILE, []);
    const incoming = [];
    const outgoing = [];
    for (const r of reqs) {
      if (r.status !== 'pending') continue;
      if (r.toId === me.id) {
        const from = publicUser(findUserById(r.fromId));
        if (from) incoming.push({ id: r.id, from, createdAt: r.createdAt });
      } else if (r.fromId === me.id) {
        const to = publicUser(findUserById(r.toId));
        if (to) outgoing.push({ id: r.id, to, createdAt: r.createdAt });
      }
    }
    return { incoming, outgoing };
  }

  function sendRequest(token, toUsername) {
    const me = findUserByToken(token);
    if (!me) {
      const err = new Error('unauthorized');
      err.status = 401;
      throw err;
    }
    if (!validUsername(toUsername)) {
      const err = new Error('invalid_username');
      err.status = 400;
      throw err;
    }
    if (normName(toUsername) === normName(me.username)) {
      const err = new Error('cannot_add_self');
      err.status = 400;
      throw err;
    }
    let target = findUserByName(toUsername);
    // Se o nick ainda não abriu o social, cria placeholder offline.
    // Quando a pessoa conectar, o login reaproveita o mesmo registro.
    if (!target) {
      target = {
        id: newId('u'),
        username: String(toUsername).trim(),
        displayName: String(toUsername).trim().slice(0, 24),
        token: null,
        status: 'offline',
        lastSeen: 0,
        createdAt: new Date().toISOString(),
        placeholder: true
      };
      saveUser(target);
    }
    ensure();
    const graph = readJson(FRIENDS_FILE, {});
    const myFriends = graph[me.id] || [];
    if (myFriends.includes(target.id)) {
      const err = new Error('already_friends');
      err.status = 400;
      throw err;
    }
    if (myFriends.length >= MAX_FRIENDS) {
      const err = new Error('friends_limit');
      err.status = 400;
      throw err;
    }
    const reqs = readJson(REQUESTS_FILE, []);
    const pendingMine = reqs.filter((r) => r.status === 'pending' && (r.fromId === me.id || r.toId === me.id));
    if (pendingMine.length >= MAX_PENDING) {
      const err = new Error('requests_limit');
      err.status = 400;
      throw err;
    }
    const existing = reqs.find(
      (r) =>
        r.status === 'pending' &&
        ((r.fromId === me.id && r.toId === target.id) || (r.fromId === target.id && r.toId === me.id))
    );
    if (existing) {
      // Se o outro já me mandou pedido, aceita automaticamente
      if (existing.fromId === target.id && existing.toId === me.id) {
        return acceptRequest(token, existing.id);
      }
      const err = new Error('request_already_sent');
      err.status = 400;
      throw err;
    }
    const req = {
      id: newId('req'),
      fromId: me.id,
      toId: target.id,
      status: 'pending',
      createdAt: new Date().toISOString()
    };
    reqs.push(req);
    writeJson(REQUESTS_FILE, reqs);
    return { ok: true, request: { id: req.id, to: publicUser(target), createdAt: req.createdAt } };
  }

  function acceptRequest(token, requestId) {
    const me = findUserByToken(token);
    if (!me) {
      const err = new Error('unauthorized');
      err.status = 401;
      throw err;
    }
    ensure();
    const reqs = readJson(REQUESTS_FILE, []);
    const req = reqs.find((r) => r.id === requestId && r.status === 'pending');
    if (!req || req.toId !== me.id) {
      const err = new Error('request_not_found');
      err.status = 404;
      throw err;
    }
    req.status = 'accepted';
    req.resolvedAt = new Date().toISOString();
    writeJson(REQUESTS_FILE, reqs);

    const graph = readJson(FRIENDS_FILE, {});
    graph[me.id] = graph[me.id] || [];
    graph[req.fromId] = graph[req.fromId] || [];
    if (!graph[me.id].includes(req.fromId)) graph[me.id].push(req.fromId);
    if (!graph[req.fromId].includes(me.id)) graph[req.fromId].push(me.id);
    writeJson(FRIENDS_FILE, graph);

    return { ok: true, friend: publicUser(findUserById(req.fromId)) };
  }

  function declineRequest(token, requestId) {
    const me = findUserByToken(token);
    if (!me) {
      const err = new Error('unauthorized');
      err.status = 401;
      throw err;
    }
    ensure();
    const reqs = readJson(REQUESTS_FILE, []);
    const req = reqs.find((r) => r.id === requestId && r.status === 'pending');
    if (!req || (req.toId !== me.id && req.fromId !== me.id)) {
      const err = new Error('request_not_found');
      err.status = 404;
      throw err;
    }
    req.status = req.fromId === me.id ? 'cancelled' : 'declined';
    req.resolvedAt = new Date().toISOString();
    writeJson(REQUESTS_FILE, reqs);
    return { ok: true };
  }

  function removeFriend(token, friendId) {
    const me = findUserByToken(token);
    if (!me) {
      const err = new Error('unauthorized');
      err.status = 401;
      throw err;
    }
    ensure();
    const graph = readJson(FRIENDS_FILE, {});
    graph[me.id] = (graph[me.id] || []).filter((id) => id !== friendId);
    graph[friendId] = (graph[friendId] || []).filter((id) => id !== me.id);
    writeJson(FRIENDS_FILE, graph);
    return { ok: true };
  }

  function conversationKey(a, b) {
    return [a, b].sort().join(':');
  }

  function getMessages(token, friendId, since) {
    const me = findUserByToken(token);
    if (!me) {
      const err = new Error('unauthorized');
      err.status = 401;
      throw err;
    }
    ensure();
    const graph = readJson(FRIENDS_FILE, {});
    if (!(graph[me.id] || []).includes(friendId)) {
      const err = new Error('not_friends');
      err.status = 403;
      throw err;
    }
    const all = readJson(MESSAGES_FILE, {});
    const key = conversationKey(me.id, friendId);
    let msgs = all[key] || [];
    if (since) {
      const t = Date.parse(since) || 0;
      msgs = msgs.filter((m) => Date.parse(m.createdAt) > t);
    }
    return {
      messages: msgs.slice(-100).map((m) => ({
        id: m.id,
        fromId: m.fromId,
        toId: m.toId,
        text: m.text,
        createdAt: m.createdAt,
        mine: m.fromId === me.id
      }))
    };
  }

  function sendMessage(token, toUserId, text) {
    const me = findUserByToken(token);
    if (!me) {
      const err = new Error('unauthorized');
      err.status = 401;
      throw err;
    }
    const body = String(text || '').trim().slice(0, MAX_MSG_LEN);
    if (!body) {
      const err = new Error('empty_message');
      err.status = 400;
      throw err;
    }
    ensure();
    const graph = readJson(FRIENDS_FILE, {});
    if (!(graph[me.id] || []).includes(toUserId)) {
      const err = new Error('not_friends');
      err.status = 403;
      throw err;
    }
    if (!findUserById(toUserId)) {
      const err = new Error('user_not_found');
      err.status = 404;
      throw err;
    }
    const all = readJson(MESSAGES_FILE, {});
    const key = conversationKey(me.id, toUserId);
    const list = all[key] || [];
    const msg = {
      id: newId('msg'),
      fromId: me.id,
      toId: toUserId,
      text: body,
      createdAt: new Date().toISOString()
    };
    list.push(msg);
    // mantém últimas 500 msgs por conversa
    all[key] = list.slice(-500);
    writeJson(MESSAGES_FILE, all);
    return {
      message: {
        id: msg.id,
        fromId: msg.fromId,
        toId: msg.toId,
        text: msg.text,
        createdAt: msg.createdAt,
        mine: true
      }
    };
  }

  function searchUsers(token, query) {
    const me = findUserByToken(token);
    if (!me) {
      const err = new Error('unauthorized');
      err.status = 401;
      throw err;
    }
    ensure();
    const q = normName(query);
    if (q.length < 2) return { users: [] };
    const users = readJson(USERS_FILE, {});
    const now = Date.now();
    const hits = Object.values(users)
      .filter((u) => u.id !== me.id && normName(u.username).includes(q))
      .slice(0, 20)
      .map((u) => publicUser(u, now));
    return { users: hits };
  }

  function mount(app) {
    ensure();

    function auth(req, res, next) {
      const header = req.headers.authorization || '';
      const token = header.startsWith('Bearer ') ? header.slice(7) : req.body?.token || req.query?.token;
      const user = findUserByToken(token);
      if (!user) return res.status(401).json({ error: 'unauthorized' });
      req.socialUser = user;
      req.socialToken = token;
      next();
    }

    app.post('/api/social/login', (req, res) => {
      try {
        const result = loginOrRegister({
          username: req.body?.username,
          displayName: req.body?.displayName
        });
        res.json(result);
      } catch (e) {
        res.status(e.status || 500).json({ error: e.message || 'login_failed' });
      }
    });

    app.post('/api/social/heartbeat', auth, (req, res) => {
      try {
        res.json(heartbeat(req.socialToken, req.body?.status));
      } catch (e) {
        res.status(e.status || 500).json({ error: e.message || 'heartbeat_failed' });
      }
    });

    app.get('/api/social/friends', auth, (req, res) => {
      try {
        res.json({ friends: getFriends(req.socialToken) });
      } catch (e) {
        res.status(e.status || 500).json({ error: e.message || 'friends_failed' });
      }
    });

    app.get('/api/social/requests', auth, (req, res) => {
      try {
        res.json(getRequests(req.socialToken));
      } catch (e) {
        res.status(e.status || 500).json({ error: e.message || 'requests_failed' });
      }
    });

    app.post('/api/social/friends/request', auth, (req, res) => {
      try {
        res.json(sendRequest(req.socialToken, req.body?.username));
      } catch (e) {
        res.status(e.status || 500).json({ error: e.message || 'request_failed' });
      }
    });

    app.post('/api/social/friends/accept', auth, (req, res) => {
      try {
        res.json(acceptRequest(req.socialToken, req.body?.requestId));
      } catch (e) {
        res.status(e.status || 500).json({ error: e.message || 'accept_failed' });
      }
    });

    app.post('/api/social/friends/decline', auth, (req, res) => {
      try {
        res.json(declineRequest(req.socialToken, req.body?.requestId));
      } catch (e) {
        res.status(e.status || 500).json({ error: e.message || 'decline_failed' });
      }
    });

    app.post('/api/social/friends/remove', auth, (req, res) => {
      try {
        res.json(removeFriend(req.socialToken, req.body?.friendId));
      } catch (e) {
        res.status(e.status || 500).json({ error: e.message || 'remove_failed' });
      }
    });

    app.get('/api/social/messages/:friendId', auth, (req, res) => {
      try {
        res.json(getMessages(req.socialToken, req.params.friendId, req.query.since));
      } catch (e) {
        res.status(e.status || 500).json({ error: e.message || 'messages_failed' });
      }
    });

    app.post('/api/social/messages', auth, (req, res) => {
      try {
        res.json(sendMessage(req.socialToken, req.body?.toUserId, req.body?.text));
      } catch (e) {
        res.status(e.status || 500).json({ error: e.message || 'send_failed' });
      }
    });

    app.get('/api/social/search', auth, (req, res) => {
      try {
        res.json(searchUsers(req.socialToken, req.query.q || ''));
      } catch (e) {
        res.status(e.status || 500).json({ error: e.message || 'search_failed' });
      }
    });

    app.get('/api/social/me', auth, (req, res) => {
      res.json({ user: publicUser(req.socialUser) });
    });
  }

  return { mount, ensure };
}

module.exports = { createSocial };
