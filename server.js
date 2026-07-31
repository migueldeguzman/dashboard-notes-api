// Notes relay for the Vesla live-agents dashboard.
// Auth: email+password checked against USERS_JSON; issues HMAC session tokens.
// Storage: SQLite (real tables), persisted to the platform's private S3 bucket
// after every write and restored from it on boot - durable across restarts
// with no external database service and nothing on GitHub.
// Image attachments live in the same private S3 bucket.

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const Database = require('better-sqlite3');
const { S3Client, PutObjectCommand, GetObjectCommand } = require('@aws-sdk/client-s3');
const { getSignedUrl } = require('@aws-sdk/s3-request-presigner');

const PORT = process.env.PORT || 10000;
const USERS = JSON.parse(process.env.USERS_JSON || '[]');
const SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '').split(',').filter(Boolean);
const SESSION_DAYS = 30;

const DB_FILE = '/tmp/ceo-tasks.sqlite';
const DB_S3_KEY = 'ceo-dashboard/db/ceo-tasks.sqlite';
let db = null;

function openDb() {
  db = new Database(DB_FILE);
  db.pragma('journal_mode = MEMORY'); // single file on disk - simplest to snapshot to S3
  db.pragma('foreign_keys = ON');
  db.exec(`
    CREATE TABLE IF NOT EXISTS notes (
      id TEXT PRIMARY KEY CHECK (length(id) = 16),
      author TEXT NOT NULL CHECK (length(author) > 0),
      text TEXT NOT NULL DEFAULT '' CHECK (length(text) <= 4000),
      images TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(images)),
      status TEXT NOT NULL DEFAULT 'open' CHECK (status IN ('open','done','deployed')),
      status_by TEXT,
      status_at TEXT,
      created_at TEXT NOT NULL
    );
    CREATE TABLE IF NOT EXISTS note_replies (
      id INTEGER PRIMARY KEY AUTOINCREMENT,
      note_id TEXT NOT NULL REFERENCES notes(id) ON DELETE CASCADE,
      author TEXT NOT NULL CHECK (length(author) > 0),
      text TEXT NOT NULL DEFAULT '' CHECK (length(text) <= 4000),
      images TEXT NOT NULL DEFAULT '[]' CHECK (json_valid(images)),
      at TEXT NOT NULL
    );
    CREATE INDEX IF NOT EXISTS idx_replies_note ON note_replies(note_id, at);
  `);
}

async function initDb() {
  if (s3) {
    try {
      const obj = await s3.send(new GetObjectCommand({ Bucket: S3_BUCKET, Key: DB_S3_KEY }));
      fs.writeFileSync(DB_FILE, Buffer.concat(await obj.Body.toArray()));
      console.log('restored ceo-tasks.sqlite from S3');
    } catch (e) {
      console.log('no db snapshot in S3 yet (' + e.name + ') - starting fresh');
    }
  }
  openDb();
}

// Push the SQLite file to S3 after every mutation. Writes are rare (a human
// posting notes), the file is tiny, and there is exactly one relay instance,
// so last-write-wins snapshotting is safe here.
async function persistDb() {
  if (!s3) return;
  await s3.send(new PutObjectCommand({
    Bucket: S3_BUCKET, Key: DB_S3_KEY,
    Body: fs.readFileSync(DB_FILE), ContentType: 'application/octet-stream',
  }));
}

function readNotes() {
  const notes = db.prepare('SELECT * FROM notes ORDER BY created_at DESC').all();
  const replies = db.prepare('SELECT * FROM note_replies ORDER BY at').all();
  const byNote = {};
  for (const r of replies) {
    (byNote[r.note_id] = byNote[r.note_id] || []).push({
      author: r.author, text: r.text, images: JSON.parse(r.images), at: r.at,
    });
  }
  return notes.map(n => ({
    id: n.id, author: n.author, text: n.text, images: JSON.parse(n.images),
    status: n.status, status_by: n.status_by, status_at: n.status_at,
    created_at: n.created_at, replies: byNote[n.id] || [],
  }));
}

function timingSafeEq(a, b) {
  const ba = Buffer.from(a), bb = Buffer.from(b);
  return ba.length === bb.length && crypto.timingSafeEqual(ba, bb);
}

function sign(payload) {
  const body = Buffer.from(JSON.stringify(payload)).toString('base64url');
  const sig = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  return `${body}.${sig}`;
}

function verifyToken(token) {
  if (!token) return null;
  const [body, sig] = token.split('.');
  if (!body || !sig) return null;
  const expect = crypto.createHmac('sha256', SECRET).update(body).digest('base64url');
  if (!timingSafeEq(sig, expect)) return null;
  try {
    const payload = JSON.parse(Buffer.from(body, 'base64url').toString());
    if (payload.exp < Date.now()) return null;
    return payload;
  } catch { return null; }
}

function json(res, code, obj, origin) {
  const headers = { 'Content-Type': 'application/json' };
  if (origin && (ALLOWED_ORIGINS.length === 0 || ALLOWED_ORIGINS.includes(origin))) {
    headers['Access-Control-Allow-Origin'] = origin;
    headers['Access-Control-Allow-Headers'] = 'Content-Type, Authorization';
    headers['Access-Control-Allow-Methods'] = 'GET, POST, OPTIONS';
  }
  res.writeHead(code, headers);
  res.end(JSON.stringify(obj));
}

function readBody(req, maxBytes = 100000) {
  return new Promise((resolve, reject) => {
    let d = '';
    req.on('data', c => { d += c; if (d.length > maxBytes) req.destroy(); });
    req.on('end', () => { try { resolve(d ? JSON.parse(d) : {}); } catch (e) { reject(e); } });
  });
}

const VALID_STATUS = ['open', 'done', 'deployed'];

// Image attachments: stored in the platform's private S3 bucket, viewed via
// short-lived presigned URLs so access stays gated by dashboard login.
const S3_BUCKET = process.env.AWS_S3_BUCKET || '';
const S3_PREFIX = 'ceo-dashboard/';
const S3_URL_TTL = 3600;
const IMAGE_MAX_BYTES = 8 * 1024 * 1024;
const IMAGE_TYPES = { 'image/png': 'png', 'image/jpeg': 'jpg', 'image/gif': 'gif', 'image/webp': 'webp' };
const s3 = S3_BUCKET ? new S3Client({ region: process.env.AWS_S3_REGION || 'us-east-1' }) : null;

function sanitizeImageKeys(images) {
  if (!Array.isArray(images)) return [];
  return images
    .filter(k => typeof k === 'string' && k.startsWith(S3_PREFIX) && /^[A-Za-z0-9/_.-]+$/.test(k))
    .slice(0, 6);
}

async function presignImages(notes) {
  if (!s3) return notes;
  const sign = key => getSignedUrl(s3, new GetObjectCommand({ Bucket: S3_BUCKET, Key: key }), { expiresIn: S3_URL_TTL });
  return Promise.all(notes.map(async n => ({
    ...n,
    image_urls: await Promise.all((n.images || []).map(sign)),
    replies: await Promise.all((n.replies || []).map(async r => ({
      ...r,
      image_urls: await Promise.all((r.images || []).map(sign)),
    }))),
  })));
}

// Live feed pass-through: the workstation publisher POSTs the encrypted
// envelope here; the dashboard GETs it with zero CDN caching. The envelope is
// ciphertext, so the GET can be public (same data as the public git branch).
const PUBLISH_SECRET = process.env.PUBLISH_SECRET || '';
let feedCache = null;
try { feedCache = JSON.parse(fs.readFileSync('/tmp/feed.json', 'utf8')); } catch {}
// Work-logs channel: same pass-through pattern as /feed but with a larger
// body allowance - the envelope carries whole (encrypted) session transcripts.
const LOGS_MAX_BYTES = 20 * 1024 * 1024;
let logsCache = null;
try { logsCache = JSON.parse(fs.readFileSync('/tmp/logs.json', 'utf8')); } catch {}

const server = http.createServer(async (req, res) => {
  const origin = req.headers.origin;
  if (req.method === 'OPTIONS') return json(res, 204, {}, origin);
  const url = new URL(req.url, 'http://x');

  try {
    if (req.method === 'GET' && url.pathname === '/health') return json(res, 200, { ok: true }, origin);

    if (url.pathname === '/feed') {
      if (req.method === 'GET') {
        res.writeHead(feedCache ? 200 : 404, {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
          'Cache-Control': 'no-store',
        });
        return res.end(feedCache ? JSON.stringify(feedCache) : '{"error":"no feed yet"}');
      }
      if (req.method === 'POST') {
        if (!PUBLISH_SECRET || req.headers['x-publish-secret'] !== PUBLISH_SECRET) {
          return json(res, 401, { error: 'unauthorized' }, origin);
        }
        feedCache = await readBody(req);
        try { fs.writeFileSync('/tmp/feed.json', JSON.stringify(feedCache)); } catch {}
        return json(res, 200, { ok: true }, origin);
      }
    }

    if (url.pathname === '/logs') {
      if (req.method === 'GET') {
        res.writeHead(logsCache ? 200 : 404, {
          'Content-Type': 'application/json',
          'Access-Control-Allow-Origin': '*',
          'Cache-Control': 'no-store',
        });
        return res.end(logsCache ? JSON.stringify(logsCache) : '{"error":"no logs yet"}');
      }
      if (req.method === 'POST') {
        if (!PUBLISH_SECRET || req.headers['x-publish-secret'] !== PUBLISH_SECRET) {
          return json(res, 401, { error: 'unauthorized' }, origin);
        }
        logsCache = await readBody(req, LOGS_MAX_BYTES);
        try { fs.writeFileSync('/tmp/logs.json', JSON.stringify(logsCache)); } catch {}
        return json(res, 200, { ok: true }, origin);
      }
    }

    if (req.method === 'POST' && url.pathname === '/login') {
      const { email, password } = await readBody(req);
      const norm = String(email || '').trim().toLowerCase();
      const user = USERS.find(u => u.email.toLowerCase() === norm);
      if (!user || !timingSafeEq(String(password || ''), user.password)) {
        return json(res, 401, { error: 'invalid credentials' }, origin);
      }
      const token = sign({ email: norm, exp: Date.now() + SESSION_DAYS * 864e5 });
      return json(res, 200, { token, email: norm }, origin);
    }

    const auth = verifyToken((req.headers.authorization || '').replace(/^Bearer /, ''));
    if (!auth) return json(res, 401, { error: 'unauthorized' }, origin);

    if (req.method === 'GET' && url.pathname === '/notes') {
      return json(res, 200, { notes: await presignImages(readNotes()) }, origin);
    }

    if (req.method === 'GET' && url.pathname === '/notes/health') {
      const n = db.prepare('SELECT count(*) c FROM notes').get().c;
      return json(res, 200, { ok: true, notes: n }, origin);
    }

    if (req.method === 'POST' && url.pathname === '/images') {
      if (!s3) return json(res, 503, { error: 'image storage not configured' }, origin);
      const { name, type, data } = await readBody(req, Math.ceil(IMAGE_MAX_BYTES * 1.4));
      const ext = IMAGE_TYPES[type];
      if (!ext) return json(res, 400, { error: 'unsupported image type' }, origin);
      let buf;
      try { buf = Buffer.from(String(data || ''), 'base64'); } catch { buf = null; }
      if (!buf || !buf.length || buf.length > IMAGE_MAX_BYTES) return json(res, 400, { error: 'bad image data' }, origin);
      const safeName = String(name || 'image').replace(/[^A-Za-z0-9_.-]/g, '_').slice(0, 60);
      const key = `${S3_PREFIX}${Date.now()}-${crypto.randomBytes(6).toString('hex')}-${safeName}.${ext}`.replace(new RegExp(`\\.${ext}\\.${ext}$`), `.${ext}`);
      await s3.send(new PutObjectCommand({ Bucket: S3_BUCKET, Key: key, Body: buf, ContentType: type }));
      return json(res, 200, { key }, origin);
    }

    if (req.method === 'POST' && url.pathname === '/notes') {
      const { text, images } = await readBody(req);
      const imgs = sanitizeImageKeys(images);
      if ((!text || !String(text).trim()) && !imgs.length) return json(res, 400, { error: 'text required' }, origin);
      const note = {
        id: crypto.randomBytes(8).toString('hex'),
        author: auth.email,
        text: String(text || '').trim().slice(0, 4000),
        images: imgs,
        created_at: new Date().toISOString(),
        status: 'open',
        status_by: null,
        status_at: null,
        replies: [],
      };
      db.prepare('INSERT INTO notes (id, author, text, images, status, created_at) VALUES (?, ?, ?, ?, ?, ?)')
        .run(note.id, note.author, note.text, JSON.stringify(note.images), note.status, note.created_at);
      await persistDb();
      return json(res, 200, { note }, origin);
    }

    const replyMatch = url.pathname.match(/^\/notes\/([a-f0-9]{16})\/reply$/);
    if (req.method === 'POST' && replyMatch) {
      const { text, images } = await readBody(req);
      const imgs = sanitizeImageKeys(images);
      if ((!text || !String(text).trim()) && !imgs.length) return json(res, 400, { error: 'text required' }, origin);
      const reply = { author: auth.email, text: String(text || '').trim().slice(0, 4000), images: imgs, at: new Date().toISOString() };
      let ok = true;
      try {
        db.prepare('INSERT INTO note_replies (note_id, author, text, images, at) VALUES (?, ?, ?, ?, ?)')
          .run(replyMatch[1], reply.author, reply.text, JSON.stringify(reply.images), reply.at);
      } catch { ok = false; } // FK violation = note does not exist
      if (ok) await persistDb();
      return ok ? json(res, 200, { reply }, origin) : json(res, 404, { error: 'note not found' }, origin);
    }

    const statusMatch = url.pathname.match(/^\/notes\/([a-f0-9]{16})\/status$/);
    if (req.method === 'POST' && statusMatch) {
      const { status } = await readBody(req);
      if (!VALID_STATUS.includes(status)) return json(res, 400, { error: 'bad status' }, origin);
      const r = db.prepare('UPDATE notes SET status = ?, status_by = ?, status_at = ? WHERE id = ?')
        .run(status, auth.email, new Date().toISOString(), statusMatch[1]);
      if (r.changes) await persistDb();
      return r.changes ? json(res, 200, { ok: true }, origin) : json(res, 404, { error: 'note not found' }, origin);
    }

    return json(res, 404, { error: 'not found' }, origin);
  } catch (e) {
    console.error(e.message);
    return json(res, 500, { error: 'server error' }, origin);
  }
});

initDb().then(() => {
  server.listen(PORT, () => console.log('notes relay listening on ' + PORT));
}).catch(e => { console.error('db init failed:', e.message); process.exit(1); });
