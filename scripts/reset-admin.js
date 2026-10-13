'use strict';
// استعادة الدخول إذا نُسيت كلمة مرور المدير:   node scripts/reset-admin.js <اسم_المستخدم> <كلمة_مرور_جديدة>
const path = require('node:path'), crypto = require('node:crypto');
const { DatabaseSync } = require('node:sqlite');
const [, , username, pass] = process.argv;
if (!username || !pass || pass.length < 8) { console.error('الاستخدام: node scripts/reset-admin.js <username> <password (8+ أحرف)>'); process.exit(1); }
const dir = path.resolve(process.env.DATA_DIR || path.join(__dirname, '..', 'data'));
const db = new DatabaseSync(path.join(dir, 'inventory.db'));
const salt = crypto.randomBytes(16).toString('hex');
const hash = crypto.scryptSync(pass, salt, 64, { N: 16384, r: 8, p: 1 }).toString('hex');
const u = db.prepare('SELECT id FROM users WHERE username = ? AND admin = 1').get(username);
if (!u) { console.error('لا يوجد مدير بهذا الاسم.'); process.exit(1); }
db.prepare('UPDATE users SET salt=?, hash=? WHERE id=?').run(salt, hash, u.id);
db.prepare('DELETE FROM sessions WHERE user_id=?').run(u.id);
console.log('تم تغيير كلمة مرور المدير', username);
