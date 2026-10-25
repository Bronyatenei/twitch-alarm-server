import crypto from 'node:crypto';
import Fastify from 'fastify';
import rawBody from 'fastify-raw-body';
import Database from 'better-sqlite3';
import admin from 'firebase-admin';

const PORT = Number(process.env.PORT || 8080);
const DB_PATH = process.env.DB_PATH || '/data/twitch-alarm.db';
const API_KEY = process.env.ADMIN_API_KEY || '';
const TWITCH_CLIENT_ID = process.env.TWITCH_CLIENT_ID || '';
const TWITCH_CLIENT_SECRET = process.env.TWITCH_CLIENT_SECRET || '';
const EVENTSUB_CALLBACK = process.env.EVENTSUB_CALLBACK || '';
const EVENTSUB_SECRET = process.env.EVENTSUB_SECRET || '';
const db = new Database(DB_PATH);
db.pragma('journal_mode = WAL');
db.exec(`
  CREATE TABLE IF NOT EXISTS watches (
    owner_id TEXT NOT NULL,
    login TEXT NOT NULL,
    user_id TEXT NOT NULL,
    enabled INTEGER NOT NULL DEFAULT 1,
    notification_only INTEGER NOT NULL DEFAULT 0,
    PRIMARY KEY (owner_id, user_id)
  );
  CREATE TABLE IF NOT EXISTS devices (
    owner_id TEXT NOT NULL,
    fcm_token TEXT NOT NULL,
    PRIMARY KEY (owner_id, fcm_token)
  );
  CREATE TABLE IF NOT EXISTS profiles (
    owner_id TEXT PRIMARY KEY,
    display_name TEXT NOT NULL
  );
  CREATE TABLE IF NOT EXISTS processed_events (
    message_id TEXT PRIMARY KEY,
    received_at INTEGER NOT NULL
  );
  CREATE TABLE IF NOT EXISTS subscriptions (
    user_id TEXT PRIMARY KEY,
    twitch_subscription_id TEXT NOT NULL
  );
`);

if (!admin.apps.length && process.env.FIREBASE_SERVICE_ACCOUNT_JSON) {
  admin.initializeApp({ credential: admin.credential.cert(JSON.parse(process.env.FIREBASE_SERVICE_ACCOUNT_JSON)) });
}

const app = Fastify({ logger: true });
await app.register(rawBody, { field: 'rawBody', global: false, encoding: false, runFirst: true });

function requireApiKey(request, reply) {
  if (!API_KEY || request.headers['x-api-key'] !== API_KEY) {
    reply.code(401).send({ error: 'unauthorized' });
    return false;
  }
  return true;
}

async function authenticateWatchlistRequest(request, reply, body) {
  const authorization = request.headers.authorization;
  if (typeof authorization === 'string' && authorization.toLowerCase().startsWith('bearer ')) {
    if (!admin.apps.length) {
      reply.code(503).send({ error: 'auth_unavailable' });
      return null;
    }
    const token = authorization.slice(7).trim();
    if (!token) {
      reply.code(401).send({ error: 'unauthorized' });
      return null;
    }
    try {
      const decoded = await admin.auth().verifyIdToken(token);
      const displayName = typeof body.displayName === 'string' ? body.displayName.trim() : '';
      if (!displayName || displayName.length > 40) {
        reply.code(400).send({ error: 'displayName must be 1..40 characters' });
        return null;
      }
      return { ownerId: decoded.uid, responseOwnerId: displayName, uid: decoded.uid, displayName };
    } catch (error) {
      request.log.warn({ code: error?.code }, 'Firebase ID token verification failed');
      reply.code(401).send({ error: 'unauthorized' });
      return null;
    }
  }
  if (!requireApiKey(request, reply)) return null;
  const ownerId = typeof body.ownerId === 'string' ? body.ownerId.trim() : '';
  if (!ownerId) {
    reply.code(400).send({ error: 'ownerId is required' });
    return null;
  }
  return { ownerId, responseOwnerId: ownerId, uid: null, displayName: null };
}

function deleteOwnerData(ownerId) {
  const remove = db.transaction(() => {
    const watches = db.prepare('DELETE FROM watches WHERE owner_id = ?').run(ownerId).changes;
    const devices = db.prepare('DELETE FROM devices WHERE owner_id = ?').run(ownerId).changes;
    const profiles = db.prepare('DELETE FROM profiles WHERE owner_id = ?').run(ownerId).changes;
    return { watches, devices, profiles, total: watches + devices + profiles };
  });
  return remove();
}
async function authenticateFirebaseUid(request, reply) {
  const authorization = request.headers.authorization;
  if (typeof authorization !== 'string' || !authorization.toLowerCase().startsWith('bearer ')) {
    reply.code(401).send({ error: 'unauthorized' });
    return null;
  }
  if (!admin.apps.length) {
    reply.code(503).send({ error: 'auth_unavailable' });
    return null;
  }
  const token = authorization.slice(7).trim();
  if (!token) {
    reply.code(401).send({ error: 'unauthorized' });
    return null;
  }
  try {
    return await admin.auth().verifyIdToken(token);
  } catch (error) {
    request.log.warn({ code: error?.code }, 'Firebase ID token verification failed');
    reply.code(401).send({ error: 'unauthorized' });
    return null;
  }
}
async function twitchToken() {
  const body = new URLSearchParams({ client_id: TWITCH_CLIENT_ID, client_secret: TWITCH_CLIENT_SECRET, grant_type: 'client_credentials' });
  const response = await fetch('https://id.twitch.tv/oauth2/token', { method: 'POST', headers: { 'content-type': 'application/x-www-form-urlencoded' }, body });
  if (!response.ok) throw new Error(`Twitch token: HTTP ${response.status}`);
  return (await response.json()).access_token;
}

async function twitch(path, options = {}) {
  const token = await twitchToken();
  const response = await fetch(`https://api.twitch.tv/helix${path}`, {
    ...options,
    headers: { 'Client-ID': TWITCH_CLIENT_ID, Authorization: `Bearer ${token}`, 'content-type': 'application/json', ...(options.headers || {}) }
  });
  if (!response.ok) throw new Error(`Twitch API ${path}: HTTP ${response.status} ${(await response.text()).slice(0, 300)}`);
  return response.status === 204 ? null : response.json();
}

async function ensureSubscription(userId) {
  if (db.prepare('SELECT 1 FROM subscriptions WHERE user_id = ?').get(userId)) return;
  const result = await twitch('/eventsub/subscriptions', {
    method: 'POST',
    body: JSON.stringify({ type: 'stream.online', version: '1', condition: { broadcaster_user_id: userId }, transport: { method: 'webhook', callback: EVENTSUB_CALLBACK, secret: EVENTSUB_SECRET } })
  });
  const subscription = result.data?.[0];
  if (!subscription) throw new Error('Twitch did not return an EventSub subscription');
  db.prepare('INSERT OR REPLACE INTO subscriptions (user_id, twitch_subscription_id) VALUES (?, ?)').run(userId, subscription.id);
}

function validSignature(request) {
  const id = request.headers['twitch-eventsub-message-id'];
  const timestamp = request.headers['twitch-eventsub-message-timestamp'];
  const signature = request.headers['twitch-eventsub-message-signature'];
  if (!id || !timestamp || !signature || !request.rawBody) return false;
  const message = id + timestamp + request.rawBody.toString('utf8');
  const expected = 'sha256=' + crypto.createHmac('sha256', EVENTSUB_SECRET).update(message).digest('hex');
  return crypto.timingSafeEqual(Buffer.from(expected), Buffer.from(signature));
}

app.get('/healthz', async () => ({ ok: true, service: 'twitch-alarm-server' }));

app.post('/eventsub/callback', { config: { rawBody: true } }, async (request, reply) => {
  if (!validSignature(request)) return reply.code(403).send({ error: 'invalid signature' });
  const type = request.headers['twitch-eventsub-message-type'];
  const id = request.headers['twitch-eventsub-message-id'];
  if (db.prepare('SELECT 1 FROM processed_events WHERE message_id = ?').get(id)) return reply.code(204).send();
  db.prepare('INSERT INTO processed_events (message_id, received_at) VALUES (?, ?)').run(id, Date.now());
  const body = request.body;
  if (type === 'webhook_callback_verification') return reply.type('text/plain').send(body.challenge);
  if (type === 'revocation') request.log.warn({ body }, 'EventSub subscription revoked');
  if (type === 'notification' && body.subscription?.type === 'stream.online') await dispatchStreamOnline(body.event, request.log);
  return reply.code(204).send();
});

async function dispatchStreamOnline(event, log) {
  const rows = db.prepare('SELECT owner_id, notification_only FROM watches WHERE user_id = ? AND enabled = 1').all(event.broadcaster_user_id);
  const tokenModes = new Map();
  for (const row of rows) {
    const notificationOnly = Boolean(row.notification_only);
    const tokens = db.prepare('SELECT fcm_token FROM devices WHERE owner_id = ?').all(row.owner_id).map(x => x.fcm_token);
    for (const token of tokens) {
      // false (alarm-enabled) wins if the same token is registered by multiple owners.
      tokenModes.set(token, tokenModes.has(token) ? (tokenModes.get(token) && notificationOnly) : notificationOnly);
    }
  }
  if (!tokenModes.size || !admin.apps.length) return;
  for (const notificationOnly of [false, true]) {
    const tokens = [...tokenModes].filter(([, mode]) => mode === notificationOnly).map(([token]) => token);
    if (!tokens.length) continue;
    const message = { data: { type: 'stream_start', streamer: event.broadcaster_user_login, streamer_name: event.broadcaster_user_name, stream_id: event.id, started_at: event.started_at, notification_only: notificationOnly ? 'true' : 'false' }, tokens };
    const result = await admin.messaging().sendEachForMulticast(message);
    log.info({ success: result.successCount, failure: result.failureCount, notificationOnly }, 'FCM stream event sent');
  }
}

app.delete('/v1/watchlists/self', async (request, reply) => {
  const decoded = await authenticateFirebaseUid(request, reply);
  if (!decoded) return;
  deleteOwnerData(decoded.uid);
  return { deleted: true, uid: decoded.uid };
});
app.delete('/v1/watchlists/:ownerId', async (request, reply) => {
  if (!requireApiKey(request, reply)) return;
  const ownerId = typeof request.params.ownerId === 'string' ? request.params.ownerId.trim() : '';
  if (!ownerId) return reply.code(400).send({ error: 'ownerId is required' });
  return { deleted: deleteOwnerData(ownerId).total, ownerId };
});
app.post('/v1/watchlists', async (request, reply) => {
  const body = request.body || {};
  const auth = await authenticateWatchlistRequest(request, reply, body);
  if (!auth) return;
  const { fcmToken, channels = [] } = body;
  if (typeof fcmToken !== 'string' || !fcmToken.trim() || !Array.isArray(channels) || channels.length > 100) {
    return reply.code(400).send({ error: 'fcmToken and up to 100 channels are required' });
  }
  const normalizedChannels = [...new Set(channels.map(channel => typeof channel === 'string' ? channel.trim().replace(/^@/, '').toLowerCase() : ''))];
  if (normalizedChannels.some(channel => !/^[a-z0-9_]{1,25}$/.test(channel))) {
    return reply.code(400).send({ error: 'channels must contain valid Twitch logins' });
  }
  let resolvedUsers = [];
  try {
    if (normalizedChannels.length) {
      const resolve = await twitch('/users?login=' + normalizedChannels.map(channel => encodeURIComponent(channel)).join('&login='));
      resolvedUsers = resolve.data || [];
      for (const user of resolvedUsers) await ensureSubscription(user.id);
    }
  } catch (error) {
    request.log.error({ err: error }, 'Twitch watchlist sync failed');
    return reply.code(502).send({ error: 'twitch_unavailable' });
  }

  const sync = db.transaction(() => {
    if (auth.displayName) {
      db.prepare('INSERT INTO profiles (owner_id, display_name) VALUES (?, ?) ON CONFLICT(owner_id) DO UPDATE SET display_name = excluded.display_name').run(auth.ownerId, auth.displayName);
    }
    db.prepare('INSERT OR IGNORE INTO devices (owner_id, fcm_token) VALUES (?, ?)').run(auth.ownerId, fcmToken.trim());
    const resolvedIds = new Set(resolvedUsers.map(user => user.id));
    const deleteMissing = db.prepare('DELETE FROM watches WHERE owner_id = ? AND user_id NOT IN (' + (resolvedIds.size ? [...resolvedIds].map(() => '?').join(',') : "SELECT ''") + ')');
    deleteMissing.run(auth.ownerId, ...resolvedIds);
    const insert = db.prepare('INSERT OR REPLACE INTO watches (owner_id, login, user_id, enabled, notification_only) VALUES (?, ?, ?, 1, 0)');
    for (const user of resolvedUsers) insert.run(auth.ownerId, user.login, user.id);
  });
  sync();
  return { ownerId: auth.responseOwnerId, uid: auth.uid, channels: resolvedUsers.map(user => user.login) };
});

app.listen({ port: PORT, host: '0.0.0.0' }).then(() => app.log.info({ port: PORT }, 'server started')).catch(error => { app.log.error(error); process.exit(1); });
