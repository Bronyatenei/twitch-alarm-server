import crypto from 'node:crypto';
import fs from 'node:fs';
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
  for (const row of rows) {
    const tokens = db.prepare('SELECT fcm_token FROM devices WHERE owner_id = ?').all(row.owner_id).map(x => x.fcm_token);
    if (!tokens.length || !admin.apps.length) continue;
    const message = { data: { type: 'stream_start', streamer: event.broadcaster_user_login, streamer_name: event.broadcaster_user_name, stream_id: event.id, started_at: event.started_at, notification_only: row.notification_only ? 'true' : 'false' }, tokens };
    const result = await admin.messaging().sendEachForMulticast(message);
    log.info({ ownerId: row.owner_id, success: result.successCount, failure: result.failureCount }, 'FCM stream event sent');
  }
}

app.post('/v1/watchlists', async (request, reply) => {
  if (!requireApiKey(request, reply)) return;
  const { ownerId, fcmToken, channels = [] } = request.body || {};
  if (!ownerId || !fcmToken || !Array.isArray(channels) || channels.length > 100) return reply.code(400).send({ error: 'ownerId, fcmToken and up to 100 channels are required' });
  db.prepare('INSERT OR IGNORE INTO devices (owner_id, fcm_token) VALUES (?, ?)').run(ownerId, fcmToken);
  const resolve = await twitch('/users?login=' + channels.map(x => encodeURIComponent(String(x).replace(/^@/, '').toLowerCase())).join('&login='));
  const insert = db.prepare('INSERT OR REPLACE INTO watches (owner_id, login, user_id, enabled, notification_only) VALUES (?, ?, ?, 1, 0)');
  for (const user of resolve.data || []) { insert.run(ownerId, user.login, user.id); await ensureSubscription(user.id); }
  return { ownerId, channels: resolve.data?.map(x => x.login) || [] };
});

app.listen({ port: PORT, host: '0.0.0.0' }).then(() => app.log.info({ port: PORT }, 'server started')).catch(error => { app.log.error(error); process.exit(1); });
