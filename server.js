// Notes relay for the Vesla live-agents dashboard.
// Auth: email+password checked against USERS_JSON; issues HMAC session tokens.
// Storage: notes.json in a private GitHub repo, accessed over SSH with a
// repo-scoped read-write deploy key (DEPLOY_KEY_B64). No broad tokens anywhere.

const http = require('http');
const crypto = require('crypto');
const fs = require('fs');
const { execFileSync } = require('child_process');

const PORT = process.env.PORT || 10000;
const USERS = JSON.parse(process.env.USERS_JSON || '[]');
const SECRET = process.env.SESSION_SECRET || crypto.randomBytes(32).toString('hex');
const ALLOWED_ORIGINS = (process.env.ALLOWED_ORIGINS || '').split(',').filter(Boolean);
const NOTES_REMOTE = process.env.NOTES_REMOTE || 'git@github.com:migueldeguzman/dashboard-notes.git';
const REPO_DIR = '/tmp/notes-repo';
const KEY_FILE = '/tmp/deploy_key';
const SESSION_DAYS = 30;

fs.writeFileSync(KEY_FILE, Buffer.from(process.env.DEPLOY_KEY_B64 || '', 'base64'));
fs.chmodSync(KEY_FILE, 0o600);
const GIT_ENV = {
  ...process.env,
  GIT_SSH_COMMAND: `ssh -i ${KEY_FILE} -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=/tmp/known_hosts`,
};

function git(args, opts = {}) {
  return execFileSync('git', args, { encoding: 'utf8', env: GIT_ENV, cwd: opts.cwd, stdio: ['pipe', 'pipe', 'pipe'] });
}

function ensureRepo() {
  if (!fs.existsSync(REPO_DIR + '/.git')) {
    git(['clone', '--depth', '1', NOTES_REMOTE, REPO_DIR]);
    git(['config', 'user.email', 'notes-relay@vesla'], { cwd: REPO_DIR });
    git(['config', 'user.name', 'notes-relay'], { cwd: REPO_DIR });
  }
}

function syncRepo() {
  ensureRepo();
  git(['fetch', '--depth', '1', 'origin', 'main'], { cwd: REPO_DIR });
  git(['reset', '--hard', 'origin/main'], { cwd: REPO_DIR });
}

function readNotes() {
  syncRepo();
  try { return JSON.parse(fs.readFileSync(REPO_DIR + '/notes.json', 'utf8')); }
  catch { return []; }
}

function writeNotes(mutate) {
  for (let attempt = 0; attempt < 2; attempt++) {
    const notes = readNotes();
    const result = mutate(notes);
    fs.writeFileSync(REPO_DIR + '/notes.json', JSON.stringify(notes, null, 2));
    git(['add', 'notes.json'], { cwd: REPO_DIR });
    git(['commit', '-m', 'notes update'], { cwd: REPO_DIR });
    try {
      git(['push', 'origin', 'main'], { cwd: REPO_DIR });
      return result;
    } catch (e) {
      if (attempt === 1) throw e;
    }
  }
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
      return json(res, 200, { notes: readNotes() }, origin);
    }

    if (req.method === 'POST' && url.pathname === '/notes') {
      const { text } = await readBody(req);
      if (!text || !String(text).trim()) return json(res, 400, { error: 'text required' }, origin);
      const note = {
        id: crypto.randomBytes(8).toString('hex'),
        author: auth.email,
        text: String(text).trim().slice(0, 4000),
        created_at: new Date().toISOString(),
        status: 'open',
        status_by: null,
        status_at: null,
        replies: [],
      };
      writeNotes(notes => { notes.unshift(note); });
      return json(res, 200, { note }, origin);
    }

    const replyMatch = url.pathname.match(/^\/notes\/([a-f0-9]{16})\/reply$/);
    if (req.method === 'POST' && replyMatch) {
      const { text } = await readBody(req);
      if (!text || !String(text).trim()) return json(res, 400, { error: 'text required' }, origin);
      const reply = { author: auth.email, text: String(text).trim().slice(0, 4000), at: new Date().toISOString() };
      const ok = writeNotes(notes => {
        const n = notes.find(x => x.id === replyMatch[1]);
        if (!n) return false;
        n.replies.push(reply);
        return true;
      });
      return ok ? json(res, 200, { reply }, origin) : json(res, 404, { error: 'note not found' }, origin);
    }

    const statusMatch = url.pathname.match(/^\/notes\/([a-f0-9]{16})\/status$/);
    if (req.method === 'POST' && statusMatch) {
      const { status } = await readBody(req);
      if (!VALID_STATUS.includes(status)) return json(res, 400, { error: 'bad status' }, origin);
      const ok = writeNotes(notes => {
        const n = notes.find(x => x.id === statusMatch[1]);
        if (!n) return false;
        n.status = status;
        n.status_by = auth.email;
        n.status_at = new Date().toISOString();
        return true;
      });
      return ok ? json(res, 200, { ok: true }, origin) : json(res, 404, { error: 'note not found' }, origin);
    }

    return json(res, 404, { error: 'not found' }, origin);
  } catch (e) {
    console.error(e.message);
    return json(res, 500, { error: 'server error' }, origin);
  }
});

server.listen(PORT, () => console.log('notes relay listening on ' + PORT));
