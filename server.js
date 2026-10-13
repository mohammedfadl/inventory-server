'use strict';
/*
 * نظام مراقبة المخزون — خادم بدون أي مكتبات خارجية (Node.js 22.13 أو أحدث فقط).
 * قاعدة البيانات: SQLite (الوحدة المدمجة node:sqlite) داخل مجلد data/
 */
const http = require('node:http');
const fs = require('node:fs');
const path = require('node:path');
const zlib = require('node:zlib');
const crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');

const PORT = parseInt(process.env.PORT || '3000', 10);
const HOST = process.env.HOST || '0.0.0.0';
const DATA_DIR = path.resolve(process.env.DATA_DIR || path.join(__dirname, 'data'));
const SESSION_HOURS = parseInt(process.env.SESSION_HOURS || '12', 10);
const TRUST_PROXY = process.env.TRUST_PROXY === '1';          // خلف nginx / Cloudflare ...
const MAX_BODY = (parseInt(process.env.MAX_BODY_MB || '300', 10)) * 1024 * 1024;
const PUBLIC_DIR = path.join(__dirname, 'public');
const PERMS = JSON.parse(fs.readFileSync(path.join(__dirname, 'permissions.json'), 'utf8')); // يُولَّد تلقائيًا من النظام

fs.mkdirSync(DATA_DIR, { recursive: true });
const db = new DatabaseSync(path.join(DATA_DIR, 'inventory.db'));
db.exec(`
  PRAGMA journal_mode = WAL;
  PRAGMA synchronous = NORMAL;
  CREATE TABLE IF NOT EXISTS users(
    id TEXT PRIMARY KEY, username TEXT UNIQUE COLLATE NOCASE NOT NULL, name TEXT,
    admin INTEGER NOT NULL DEFAULT 0, active INTEGER NOT NULL DEFAULT 1,
    perms TEXT NOT NULL DEFAULT '{}', salt TEXT NOT NULL, hash TEXT NOT NULL, created TEXT NOT NULL);
  CREATE TABLE IF NOT EXISTS sessions(
    tokhash TEXT PRIMARY KEY, user_id TEXT NOT NULL, expires INTEGER NOT NULL);
  CREATE TABLE IF NOT EXISTS stores(
    name TEXT PRIMARY KEY, json TEXT NOT NULL, rev INTEGER NOT NULL DEFAULT 1, updated TEXT, updated_by TEXT);
  CREATE TABLE IF NOT EXISTS audit(
    id INTEGER PRIMARY KEY AUTOINCREMENT, ts TEXT NOT NULL, user TEXT, ip TEXT, action TEXT, detail TEXT);
`);
const q = {
  userByName: db.prepare('SELECT * FROM users WHERE username = ?'),
  userById: db.prepare('SELECT * FROM users WHERE id = ?'),
  userCount: db.prepare('SELECT COUNT(*) c FROM users'),
  allUsers: db.prepare('SELECT id,username,name,admin,active,perms,created FROM users ORDER BY created'),
  insUser: db.prepare('INSERT INTO users(id,username,name,admin,active,perms,salt,hash,created) VALUES(?,?,?,?,?,?,?,?,?)'),
  delUser: db.prepare('DELETE FROM users WHERE id = ? AND admin = 0'),
  insSess: db.prepare('INSERT INTO sessions(tokhash,user_id,expires) VALUES(?,?,?)'),
  getSess: db.prepare('SELECT user_id, expires FROM sessions WHERE tokhash = ?'),
  delSess: db.prepare('DELETE FROM sessions WHERE tokhash = ?'),
  delUserSess: db.prepare('DELETE FROM sessions WHERE user_id = ?'),
  purgeSess: db.prepare('DELETE FROM sessions WHERE expires < ?'),
  getStore: db.prepare('SELECT json, rev FROM stores WHERE name = ?'),
  revStore: db.prepare('SELECT rev FROM stores WHERE name = ?'),
  putStore: db.prepare(`INSERT INTO stores(name,json,rev,updated,updated_by) VALUES(?,?,1,?,?)
     ON CONFLICT(name) DO UPDATE SET json=excluded.json, rev=stores.rev+1, updated=excluded.updated, updated_by=excluded.updated_by`),
  audit: db.prepare('INSERT INTO audit(ts,user,ip,action,detail) VALUES(?,?,?,?,?)'),
};
const now = () => new Date().toISOString();

// ---------- كلمات المرور والجلسات ----------
function hashPass(pass, salt) { return crypto.scryptSync(pass, salt, 64, { N: 16384, r: 8, p: 1 }).toString('hex'); }
function newUserRecord(pass) { const salt = crypto.randomBytes(16).toString('hex'); return { salt, hash: hashPass(pass, salt) }; }
function checkPass(u, pass) {
  const a = Buffer.from(hashPass(pass, u.salt), 'hex'), b = Buffer.from(u.hash, 'hex');
  return a.length === b.length && crypto.timingSafeEqual(a, b);
}
const sha = s => crypto.createHash('sha256').update(s).digest('hex');
function createSession(userId) {
  const tok = crypto.randomBytes(32).toString('base64url');
  q.insSess.run(sha(tok), userId, Date.now() + SESSION_HOURS * 3600e3);
  return tok;
}
function parseCookies(req) {
  const o = {}; (req.headers.cookie || '').split(';').forEach(p => { const i = p.indexOf('='); if (i > 0) o[p.slice(0, i).trim()] = decodeURIComponent(p.slice(i + 1).trim()); });
  return o;
}
function currentUser(req) {
  const tok = parseCookies(req).sid; if (!tok) return null;
  const s = q.getSess.get(sha(tok)); if (!s) return null;
  if (s.expires < Date.now()) { q.delSess.run(sha(tok)); return null; }
  const u = q.userById.get(s.user_id); return (u && u.active) ? u : null;
}
const isSecure = req => req.socket.encrypted || (TRUST_PROXY && req.headers['x-forwarded-proto'] === 'https');
function sessionCookie(req, tok, maxAge) {
  return `sid=${encodeURIComponent(tok)}; HttpOnly; SameSite=Strict; Path=/; Max-Age=${maxAge}${isSecure(req) ? '; Secure' : ''}`;
}
function clientIp(req) { return (TRUST_PROXY && String(req.headers['x-forwarded-for'] || '').split(',')[0].trim()) || req.socket.remoteAddress || ''; }

// ---------- حماية من تخمين كلمات المرور ----------
const fails = new Map(); // key -> {n, until}
function lockedOut(key) { const f = fails.get(key); return f && f.until > Date.now(); }
function noteFail(key) { const f = fails.get(key) || { n: 0, until: 0 }; f.n++; if (f.n >= 5) { f.until = Date.now() + 10 * 60e3; f.n = 0; } fails.set(key, f); }

// ---------- الصلاحيات ----------
const permsOf = u => { try { return JSON.parse(u.perms || '{}'); } catch { return {}; } };
const can = (u, tab, a) => !!u && (u.admin === 1 || !!(permsOf(u)[tab] && permsOf(u)[tab][a]));
const canReadData = u => u.admin === 1 || Object.values(permsOf(u)).some(p => p && p.v);
const canWriteStore = (u, store) => u.admin === 1 || (PERMS.storeOwnerTabs[store] || []).some(t => can(u, t, 'e'));
function cleanPerms(p) {
  const out = {};
  for (const t of PERMS.tabs) { const x = p && p[t]; if (x && (x.v || x.e || x.x)) out[t] = { v: 1, e: x.e ? 1 : 0, x: x.x ? 1 : 0 }; }
  return out;
}
const publicUser = u => ({ id: u.id, username: u.username, name: u.name || u.username, admin: u.admin === 1, active: u.active === 1, perms: permsOf(u) });

// ---------- أدوات HTTP ----------
function send(req, res, code, body, headers = {}) {
  const isStr = typeof body === 'string';
  let buf = Buffer.isBuffer(body) ? body : Buffer.from(isStr ? body : JSON.stringify(body));
  const h = { 'Content-Type': isStr ? 'text/plain; charset=utf-8' : 'application/json; charset=utf-8', 'Cache-Control': 'no-store', ...headers };
  if (buf.length > 1024 && /\bgzip\b/.test(req.headers['accept-encoding'] || '')) { buf = zlib.gzipSync(buf, { level: 5 }); h['Content-Encoding'] = 'gzip'; }
  h['Content-Length'] = buf.length; res.writeHead(code, h); res.end(buf);
}
const json = (req, res, code, obj, headers) => send(req, res, code, obj, headers);
const fail = (req, res, code, msg) => json(req, res, code, { error: msg });
function readBody(req) {
  return new Promise((resolve, reject) => {
    let size = 0; const chunks = [];
    req.on('data', c => { size += c.length; if (size > MAX_BODY) { reject(Object.assign(new Error('too large'), { code: 413 })); req.destroy(); } else chunks.push(c); });
    req.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
    req.on('error', reject);
  });
}
const SEC_HEADERS = {
  'X-Content-Type-Options': 'nosniff', 'X-Frame-Options': 'SAMEORIGIN', 'Referrer-Policy': 'same-origin',
  'Content-Security-Policy': "default-src 'self'; script-src 'self' 'unsafe-inline' https://cdnjs.cloudflare.com; style-src 'self' 'unsafe-inline' https://fonts.googleapis.com; font-src https://fonts.gstatic.com; img-src 'self' data: blob:; connect-src 'self'; frame-ancestors 'self'; object-src 'none'; base-uri 'self'",
};
const STATIC = { '/': ['index.html', 'text/html; charset=utf-8'], '/index.html': ['index.html', 'text/html; charset=utf-8'], '/server-adapter.js': ['server-adapter.js', 'application/javascript; charset=utf-8'],
  '/xlsx.full.min.js': ['xlsx.full.min.js', 'application/javascript; charset=utf-8'] };   // اختياري: انظر README

// ---------- الموجّه ----------
async function handle(req, res) {
  const url = new URL(req.url, 'http://x'); const p = url.pathname;
  for (const [k, v] of Object.entries(SEC_HEADERS)) res.setHeader(k, v);

  if (req.method === 'GET' && STATIC[p]) {
    const [file, type] = STATIC[p];
    if (!fs.existsSync(path.join(PUBLIC_DIR, file))) return fail(req, res, 404, 'not found');
    return send(req, res, 200, fs.readFileSync(path.join(PUBLIC_DIR, file)), { 'Content-Type': type, 'Cache-Control': 'no-cache' });
  }
  if (!p.startsWith('/api/')) return fail(req, res, 404, 'not found');

  // حماية CSRF: أي طلب يغيّر البيانات يجب أن يحمل هذا الترويس (المتصفح لا يرسله من موقع آخر)
  if (req.method !== 'GET' && req.headers['x-requested-with'] !== 'inventory') return fail(req, res, 403, 'forbidden');
  const ip = clientIp(req);

  if (p === '/api/status' && req.method === 'GET') return json(req, res, 200, { needsSetup: q.userCount.get().c === 0 });

  if (p === '/api/setup' && req.method === 'POST') {
    if (q.userCount.get().c > 0) return fail(req, res, 409, 'تم إنشاء حساب المدير مسبقًا');
    const b = JSON.parse(await readBody(req) || '{}');
    const username = String(b.username || '').trim(), pass = String(b.password || '');
    if (!/^[A-Za-z0-9_.\-@؀-ۿ]{2,40}$/.test(username)) return fail(req, res, 400, 'اسم المستخدم غير صالح');
    if (pass.length < 8) return fail(req, res, 400, 'كلمة مرور المدير يجب ألا تقل عن 8 أحرف');
    const id = 'u' + crypto.randomBytes(6).toString('hex'), r = newUserRecord(pass);
    q.insUser.run(id, username, String(b.name || username).trim(), 1, 1, '{}', r.salt, r.hash, now());
    q.audit.run(now(), username, ip, 'setup', 'admin created');
    return json(req, res, 200, { ok: true }, { 'Set-Cookie': sessionCookie(req, createSession(id), SESSION_HOURS * 3600) });
  }

  if (p === '/api/login' && req.method === 'POST') {
    const b = JSON.parse(await readBody(req) || '{}');
    const username = String(b.username || '').trim(), key = ip + '|' + username.toLowerCase();
    if (lockedOut(key) || lockedOut(ip)) return fail(req, res, 429, 'محاولات كثيرة خاطئة. حاول بعد 10 دقائق.');
    const u = q.userByName.get(username);
    if (!u || !u.active || !checkPass(u, String(b.password || ''))) {
      noteFail(key); noteFail(ip); q.audit.run(now(), username, ip, 'login_failed', '');
      return fail(req, res, 401, 'اسم المستخدم أو كلمة المرور غير صحيحة');
    }
    fails.delete(key); q.purgeSess.run(Date.now()); q.audit.run(now(), u.username, ip, 'login', '');
    return json(req, res, 200, { ok: true }, { 'Set-Cookie': sessionCookie(req, createSession(u.id), SESSION_HOURS * 3600) });
  }

  if (p === '/api/logout' && req.method === 'POST') {
    const t = parseCookies(req).sid; if (t) q.delSess.run(sha(t));
    return json(req, res, 200, { ok: true }, { 'Set-Cookie': sessionCookie(req, '', 0) });
  }

  // ------- كل ما بعد هذا يحتاج تسجيل دخول -------
  const me = currentUser(req);
  if (!me) return fail(req, res, 401, 'غير مسجّل الدخول');

  if (p === '/api/me' && req.method === 'GET') return json(req, res, 200, { user: publicUser(me) });

  if (p === '/api/me/password' && req.method === 'POST') {
    const b = JSON.parse(await readBody(req) || '{}');
    if (!checkPass(me, String(b.current || ''))) return fail(req, res, 400, 'كلمة المرور الحالية غير صحيحة');
    const np = String(b.password || ''); if (np.length < (me.admin ? 8 : 6)) return fail(req, res, 400, 'كلمة المرور الجديدة قصيرة');
    const r = newUserRecord(np); db.prepare('UPDATE users SET salt=?, hash=? WHERE id=?').run(r.salt, r.hash, me.id);
    q.audit.run(now(), me.username, ip, 'password_change', ''); return json(req, res, 200, { ok: true });
  }

  let m;
  if ((m = p.match(/^\/api\/data\/([A-Za-z]+)$/))) {
    const store = m[1];
    if (!PERMS.stores.includes(store)) return fail(req, res, 404, 'unknown store');
    if (req.method === 'GET') {
      if (!canReadData(me)) return fail(req, res, 403, 'ليست لديك صلاحية');
      const row = q.getStore.get(store);
      return send(req, res, 200, row ? row.json : '[]', { 'Content-Type': 'application/json; charset=utf-8', 'X-Rev': String(row ? row.rev : 0) });
    }
    if (req.method === 'PUT') {
      if (!canWriteStore(me, store)) return fail(req, res, 403, 'ليست لديك صلاحية التعديل على هذه البيانات');
      const body = await readBody(req);
      let parsed; try { parsed = JSON.parse(body); } catch { return fail(req, res, 400, 'bad json'); }
      if (!Array.isArray(parsed)) return fail(req, res, 400, 'expected array');
      const cur = q.revStore.get(store), curRev = cur ? cur.rev : 0;
      const base = req.headers['if-match'];
      if (base !== undefined && String(curRev) !== String(base)) return json(req, res, 409, { error: 'تم تعديل هذه البيانات من مستخدم آخر. أعد تحميل الصفحة ثم أعد المحاولة.', rev: curRev });
      q.putStore.run(store, body, now(), me.username);
      q.audit.run(now(), me.username, ip, 'save', `${store} (${parsed.length})`);
      return json(req, res, 200, { ok: true, rev: curRev + 1 });
    }
  }

  if (p === '/api/reset' && req.method === 'POST') {
    if (!me.admin) return fail(req, res, 403, 'لمدير النظام فقط');
    for (const s of PERMS.backupStores) q.putStore.run(s, '[]', now(), me.username);
    q.audit.run(now(), me.username, ip, 'reset_all', ''); return json(req, res, 200, { ok: true });
  }

  // ------- إدارة المستخدمين (مدير فقط) -------
  if (p === '/api/users' || p.startsWith('/api/users/')) {
    if (!me.admin) return fail(req, res, 403, 'لمدير النظام فقط');
    if (p === '/api/users' && req.method === 'GET') return json(req, res, 200, { users: q.allUsers.all().map(publicUser) });
    if (p === '/api/users' && req.method === 'POST') {
      const b = JSON.parse(await readBody(req) || '{}');
      const username = String(b.username || '').trim(), pass = String(b.password || '');
      if (!/^[A-Za-z0-9_.\-@؀-ۿ]{2,40}$/.test(username)) return fail(req, res, 400, 'اسم المستخدم غير صالح');
      if (pass.length < 6) return fail(req, res, 400, 'كلمة المرور يجب ألا تقل عن 6 أحرف');
      if (q.userByName.get(username)) return fail(req, res, 409, 'اسم المستخدم مستخدم مسبقًا');
      const id = 'u' + crypto.randomBytes(6).toString('hex'), r = newUserRecord(pass);
      q.insUser.run(id, username, String(b.name || username).trim(), 0, b.active === false ? 0 : 1, JSON.stringify(cleanPerms(b.perms)), r.salt, r.hash, now());
      q.audit.run(now(), me.username, ip, 'user_add', username); return json(req, res, 200, { ok: true, id });
    }
    if ((m = p.match(/^\/api\/users\/([A-Za-z0-9]+)$/))) {
      const t = q.userById.get(m[1]); if (!t || t.admin) return fail(req, res, 404, 'المستخدم غير موجود');
      if (req.method === 'PUT') {
        const b = JSON.parse(await readBody(req) || '{}');
        const username = String(b.username || t.username).trim();
        if (!/^[A-Za-z0-9_.\-@؀-ۿ]{2,40}$/.test(username)) return fail(req, res, 400, 'اسم المستخدم غير صالح');
        const dup = q.userByName.get(username); if (dup && dup.id !== t.id) return fail(req, res, 409, 'اسم المستخدم مستخدم مسبقًا');
        db.prepare('UPDATE users SET username=?, name=?, active=?, perms=? WHERE id=?')
          .run(username, String(b.name || username).trim(), b.active === false ? 0 : 1, JSON.stringify(cleanPerms(b.perms)), t.id);
        if (b.password) {
          if (String(b.password).length < 6) return fail(req, res, 400, 'كلمة المرور يجب ألا تقل عن 6 أحرف');
          const r = newUserRecord(String(b.password)); db.prepare('UPDATE users SET salt=?, hash=? WHERE id=?').run(r.salt, r.hash, t.id);
        }
        if (b.active === false || b.password) q.delUserSess.run(t.id);  // إنهاء جلساته فورًا
        q.audit.run(now(), me.username, ip, 'user_edit', username); return json(req, res, 200, { ok: true });
      }
      if (req.method === 'DELETE') { q.delUserSess.run(t.id); q.delUser.run(t.id); q.audit.run(now(), me.username, ip, 'user_delete', t.username); return json(req, res, 200, { ok: true }); }
    }
  }
  if (p === '/api/audit' && req.method === 'GET') {
    if (!me.admin) return fail(req, res, 403, 'لمدير النظام فقط');
    const n = Math.min(parseInt(url.searchParams.get('limit') || '200', 10) || 200, 2000);
    return json(req, res, 200, { rows: db.prepare('SELECT ts,user,ip,action,detail FROM audit ORDER BY id DESC LIMIT ?').all(n) });
  }
  return fail(req, res, 404, 'not found');
}

const server = http.createServer((req, res) => {
  handle(req, res).catch(err => {
    if (res.headersSent) return res.end();
    const code = err.code === 413 ? 413 : (err instanceof SyntaxError ? 400 : 500);
    if (code === 500) console.error(err);
    fail(req, res, code, code === 413 ? 'حجم البيانات كبير جدًا' : code === 400 ? 'bad request' : 'خطأ في الخادم');
  });
});
server.requestTimeout = 10 * 60e3;
server.listen(PORT, HOST, () => console.log(`Inventory server on http://${HOST}:${PORT}  (data: ${DATA_DIR})`));
for (const s of ['SIGINT', 'SIGTERM']) process.on(s, () => { try { db.exec('PRAGMA wal_checkpoint(TRUNCATE)'); db.close(); } catch {} process.exit(0); });
