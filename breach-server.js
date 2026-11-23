// Save this file as server.js (remove .txt if your download adds it).
// Requires Node.js 24+. Install: npm install express socket.io express-rate-limit
// Run: node server.js   Open: http://localhost:3000
// Production: NODE_ENV=production node server.js behind an HTTPS reverse proxy.
// Set DATA_DIR to a persistent disk directory. Run ONE server process.
'use strict';
const express = require('express');
const { Server } = require('socket.io');
const { rateLimit } = require('express-rate-limit');
const { DatabaseSync } = require('node:sqlite');
const crypto = require('node:crypto');
const { promisify } = require('node:util');
const fs = require('node:fs');
const path = require('node:path');
const http = require('node:http');
const scrypt = promisify(crypto.scrypt);
const app = express();
const server = http.createServer(app);
const production = process.env.NODE_ENV === 'production';
const port = Number(process.env.PORT || 3000);
const dataDir = path.resolve(process.env.DATA_DIR || './data');
fs.mkdirSync(dataDir, { recursive: true });
const db = new DatabaseSync(path.join(dataDir, 'breach.sqlite'));
db.exec(`PRAGMA journal_mode=WAL; PRAGMA foreign_keys=ON;
 CREATE TABLE IF NOT EXISTS users (
 id INTEGER PRIMARY KEY, username TEXT NOT NULL UNIQUE COLLATE NOCASE,
 salt TEXT NOT NULL, hash TEXT NOT NULL);
 CREATE TABLE IF NOT EXISTS sessions (
 token TEXT PRIMARY KEY, user_id INTEGER NOT NULL REFERENCES users(id), expires INTEGER NOT NULL);
 CREATE INDEX IF NOT EXISTS sessions_expiry ON sessions(expires);`);
if (process.env.TRUST_PROXY_HOPS) app.set('trust proxy', Number(process.env.TRUST_PROXY_HOPS));
app.disable('x-powered-by');
app.use((req, res, next) => {
 res.setHeader('X-Content-Type-Options', 'nosniff');
 res.setHeader('Referrer-Policy', 'same-origin');
 res.setHeader('X-Frame-Options', 'DENY');
 res.setHeader('Cache-Control', 'no-store');
 next();
});
app.use(express.json({ limit: '2kb' }));
const lifetime = 7 * 24 * 60 * 60 * 1000;
const digest = value => crypto.createHash('sha256').update(value).digest('hex');
function cookieToken(req) {
 const match = /(?:^|;\s*)breach_session=([a-f0-9]{64})(?:;|$)/.exec(req.headers.cookie || '');
 return match ? match[1] : null;
}
function session(req) {
 const token = cookieToken(req);
 if (!token) return null;
 return db.prepare(`SELECT users.id, users.username, sessions.expires FROM sessions
 JOIN users ON users.id=sessions.user_id WHERE sessions.token=? AND sessions.expires>?`)
 .get(digest(token), Date.now()) || null;
}
function issueSession(res, id) {
 const token = crypto.randomBytes(32).toString('hex');
 db.prepare('INSERT INTO sessions VALUES(?,?,?)').run(digest(token), id, Date.now() + lifetime);
 res.cookie('breach_session', token, { httpOnly: true, secure: production, sameSite: 'strict', maxAge: lifetime, path: '/' });
}
function originAllowed(req) {
 const origin = req.headers.origin;
 if (!origin) return false;
 const expected = process.env.PUBLIC_ORIGIN || req.protocol + '://' + req.get('host');
 return origin === expected;
}
app.use('/api', (req, res, next) => {
 if (req.method !== 'GET' && !originAllowed(req)) return res.status(403).json({ error: 'Open this page on the server URL.' });
 next();
});
const authLimit = rateLimit({ windowMs: 15 * 60 * 1000, limit: 30,
 standardHeaders: 'draft-7', legacyHeaders: false,
 message: { error: 'Too many attempts. Try again in 15 minutes.' } });
let hashing = 0;
async function derive(password, salt) {
 if (hashing >= 8) { const e = new Error('Server busy. Try again shortly.'); e.status = 503; throw e; }
 hashing++;
 try { return await scrypt(password, salt, 64); } finally { hashing--; }
}
function credentials(req, res) {
 const { username, password } = req.body || {};
 if (typeof username !== 'string' || !/^[a-zA-Z0-9_]{3,20}$/.test(username) ||
 typeof password !== 'string' || password.length < 12 || password.length > 128) {
 res.status(400).json({ error: 'Use a 3–20 character username (letters, numbers, underscore) and a 12–128 character password.' });
 return null;
 }
 return { username, password };
}
app.post('/api/signup', authLimit, async (req, res, next) => {
 const c = credentials(req, res); if (!c) return;
 try {
 const salt = crypto.randomBytes(16).toString('hex');
 const hash = (await derive(c.password, salt)).toString('hex');
 let result;
 try { result = db.prepare('INSERT INTO users(username,salt,hash) VALUES(?,?,?)').run(c.username, salt, hash); }
 catch (e) {
 if (db.prepare('SELECT id FROM users WHERE username=?').get(c.username)) return res.status(409).json({ error: 'That username is already taken.' });
 throw e;
 }
 issueSession(res, Number(result.lastInsertRowid));
 res.status(201).json({ username: c.username });
 } catch (e) { next(e); }
});
app.post('/api/login', authLimit, async (req, res, next) => {
 const c = credentials(req, res); if (!c) return;
 try {
 const user = db.prepare('SELECT * FROM users WHERE username=?').get(c.username);
 const hash = await derive(c.password, user ? user.salt : '00000000000000000000000000000000');
 const expected = user ? Buffer.from(user.hash, 'hex') : Buffer.alloc(64);
 const valid = crypto.timingSafeEqual(hash, expected);
 if (!user || !valid) return res.status(401).json({ error: 'Username or password is incorrect.' });
 issueSession(res, user.id);
 res.json({ username: user.username });
 } catch (e) { next(e); }
});
app.get('/api/me', (req, res) => {
 const user = session(req);
 if (!user) return res.status(401).json({ error: 'Please log in.' });
 res.json({ username: user.username });
});
app.post('/api/logout', (req, res) => {
 const token = cookieToken(req);
 if (token) {
 const key = digest(token);
 db.prepare('DELETE FROM sessions WHERE token=?').run(key);
 for (const socket of io.sockets.sockets.values()) if (socket.data.sessionKey === key) socket.disconnect(true);
 }
 res.clearCookie('breach_session', { httpOnly: true, secure: production, sameSite: 'strict', path: '/' });
 res.json({ ok: true });
});
const io = new Server(server, { maxHttpBufferSize: 4096, allowRequest: (req, done) => {
 const expected = process.env.PUBLIC_ORIGIN || (production ? 'https://' : 'http://') + req.headers.host;
 done(null, req.headers.origin === expected);
} });
const players = new Map();
const rooms = new Map();
const allowedKeys = new Set(['up', 'down', 'left', 'right']);
function snapshot(room) {
 return [...(rooms.get(room) || [])].map(id => {
 const p = players.get(id);
 return { id, username: p.username, x: p.x, y: p.y, color: p.color };
 });
}
function leave(socket) {
 const p = players.get(socket.id); if (!p) return;
 const room = p.room;
 players.delete(socket.id);
 const members = rooms.get(room);
 if (members) { members.delete(socket.id); if (!members.size) rooms.delete(room); }
 socket.leave(room);
 io.to(room).emit('state', snapshot(room));
}
io.use((socket, next) => {
 const user = session(socket.request);
 if (!user) return next(new Error('Please log in again.'));
 socket.data.user = user;
 socket.data.sessionKey = digest(cookieToken(socket.request));
 next();
});
io.on('connection', socket => {
 let windowStart = Date.now(), events = 0, lastJoin = 0;
 socket.use((packet, next) => {
 const now = Date.now();
 if (now - windowStart > 1000) { windowStart = now; events = 0; }
 if (++events > 90) return socket.disconnect(true);
 if (socket.data.user.expires <= now) return socket.disconnect(true);
 next();
 });
 socket.on('join', (value, ack) => {
 const reply = typeof ack === 'function' ? ack : () => {};
 if (Date.now() - lastJoin < 1000) return reply({ error: 'Wait a second before joining again.' });
 lastJoin = Date.now();
 if (typeof value !== 'string' || !/^[a-zA-Z0-9_-]{1,24}$/.test(value)) return reply({ error: 'Room name: 1–24 letters, numbers, underscores or hyphens.' });
 const room = 'game:' + value.toLowerCase();
 if ((rooms.get(room)?.size || 0) >= 16 && players.get(socket.id)?.room !== room) return reply({ error: 'Room is full (16 players).' });
 if (!rooms.has(room) && rooms.size >= 100) return reply({ error: 'Server is full.' });
 // Only one active player per account on this server.
 for (const [id, p] of players) if (p.userId === socket.data.user.id && id !== socket.id) io.sockets.sockets.get(id)?.disconnect(true);
 leave(socket);
 if (!rooms.has(room)) rooms.set(room, new Set());
 rooms.get(room).add(socket.id);
 players.set(socket.id, { userId: socket.data.user.id, username: socket.data.user.username,
 room, x: 40 + Math.random() * 720, y: 40 + Math.random() * 420,
 color: '#' + crypto.randomBytes(3).toString('hex'), keys: {} });
 socket.join(room);
 reply({ ok: true, id: socket.id, room: value.toLowerCase() });
 io.to(room).emit('state', snapshot(room));
 });
 socket.on('input', keys => {
 const p = players.get(socket.id);
 if (!p || !keys || typeof keys !== 'object' || Array.isArray(keys)) return;
 p.keys = {};
 for (const key of allowedKeys) p.keys[key] = keys[key] === true;
 p.inputAt = Date.now();
 });
 socket.on('disconnect', () => leave(socket));
});
setInterval(() => {
 const now = Date.now();
 for (const [id, p] of players) {
 const socket = io.sockets.sockets.get(id);
 if (!socket || socket.data.user.expires <= now) { socket?.disconnect(true); continue; }
 if (!p.inputAt || now - p.inputAt > 500) p.keys = {};
 let dx = Number(!!p.keys.right) - Number(!!p.keys.left);
 let dy = Number(!!p.keys.down) - Number(!!p.keys.up);
 const length = Math.hypot(dx, dy) || 1;
 p.x = Math.max(12, Math.min(788, p.x + dx / length * 8));
 p.y = Math.max(12, Math.min(488, p.y + dy / length * 8));
 }
 for (const room of rooms.keys()) io.to(room).emit('state', snapshot(room));
}, 1000 / 30).unref();
setInterval(() => db.prepare('DELETE FROM sessions WHERE expires<=?').run(Date.now()), 60000).unref();
const page = `<!DOCTYPE html>
<html lang="en"><head><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>BREACH Online</title><style>
*{box-sizing:border-box}body{margin:0;min-height:100vh;background:radial-gradient(ellipse at top left,#273a48,#0b1017 65%);color:#edf2f6;font:16px system-ui;padding:24px}.shell{max-width:1000px;margin:32px auto}h1{font-size:48px;letter-spacing:6px;margin:8px 0}.tag{color:#ffc66e;letter-spacing:3px;font-size:12px}p{color:#a8b7c5;line-height:1.6}.card{background:#151e29;border:1px solid #344151;border-radius:20px;padding:26px;margin-top:24px}button,input{font:inherit;border-radius:8px;padding:12px}button{cursor:pointer;background:#ffc66e;color:#151a22;border:0;font-weight:700}button:disabled{opacity:.5;cursor:wait}input{background:#0d151e;color:white;border:1px solid #3c4c5e;width:100%}label{display:block;margin:16px 0 7px}.tabs,.row{display:flex;gap:12px;flex-wrap:wrap;align-items:center}.tabs button[aria-selected=false]{background:#243141;color:#b7c5d2}.submit{margin-top:22px;width:100%}.status{min-height:26px;color:#ffd597;margin-top:16px}.hide{display:none}canvas{width:100%;background:#0b121b;border:1px solid #344151;border-radius:12px;display:block;margin:20px 0;touch-action:none}#room{max-width:220px}.pad{display:flex;gap:8px;flex-wrap:wrap}.pad button{touch-action:none;user-select:none;min-width:65px}button:focus-visible,input:focus-visible{outline:3px solid #75baff;outline-offset:3px}
</style></head><body><main class="shell"><span class="tag">BREACH / PLAYER ACCESS</span><h1>GEAR UP.</h1><p>Make an account, share a room name, and move together online.</p>
<section id="auth" class="card"><div class="tabs"><button id="login" aria-selected="true">Log in</button><button id="signup" aria-selected="false">Sign up</button></div>
<form id="form"><label for="username">Username</label><input id="username" autocomplete="username" pattern="[A-Za-z0-9_]{3,20}" minlength="3" maxlength="20" required><label for="password">Password</label><input id="password" type="password" autocomplete="current-password" minlength="12" maxlength="128" required><p>Use 3–20 letters, numbers or underscores for your username, and at least 12 characters for your password.</p><button class="submit" id="submit">Log in</button></form></section>
<section id="game" class="card hide"><div class="row"><strong id="who"></strong><button id="logout">Log out</button></div><p>Enter the same room name as your friends. Each room holds up to 16 players.</p><div class="row"><input id="room" value="lobby" maxlength="24" aria-label="Room name"><button id="join">Join room</button></div><p id="roomInfo">Choose a room to start.</p><canvas id="arena" width="800" height="500" aria-label="Multiplayer movement arena"></canvas><p>Move with WASD, arrow keys, or the buttons below. This is a movement lobby; your original game code has not been supplied.</p><div class="pad"><button data-key="up">Up</button><button data-key="left">Left</button><button data-key="down">Down</button><button data-key="right">Right</button></div></section><div id="status" class="status" role="status" aria-live="polite"></div></main>
<script src="/socket.io/socket.io.js"></script><script>
'use strict';
const $ = id => document.getElementById(id);
let signup = false, socket = null, state = [], self = '', joined = false;
const keys = { up:false, down:false, left:false, right:false };
function message(text) { $('status').textContent = text; }
function mode(value) { signup = value; $('login').setAttribute('aria-selected', String(!value)); $('signup').setAttribute('aria-selected', String(value)); $('submit').textContent = value ? 'Create account' : 'Log in'; $('password').autocomplete = value ? 'new-password' : 'current-password'; message(''); }
$('login').onclick = () => mode(false); $('signup').onclick = () => mode(true);
async function api(url, data) {
 const res = await fetch(url, data === undefined ? { credentials:'same-origin' } : { method:'POST', credentials:'same-origin', headers:{'Content-Type':'application/json'}, body:JSON.stringify(data) });
 const result = await res.json(); if (!res.ok) throw new Error(result.error || 'Request failed.'); return result;
}
function showAuth() { socket?.disconnect(); socket = null; joined = false; state = []; clearKeys(); $('auth').classList.remove('hide'); $('game').classList.add('hide'); }
function showGame(user) {
 $('auth').classList.add('hide'); $('game').classList.remove('hide'); $('who').textContent = 'Signed in as ' + user.username; message('Connected account. Join a room.');
 socket?.disconnect(); socket = io({ autoConnect:false });
 socket.on('connect', () => { self = socket.id; joined = false; message('Online. Join a room.'); });
 socket.on('state', players => { state = players; });
 socket.on('connect_error', error => message(error.message));
 socket.on('disconnect', () => { joined = false; state = []; clearKeys(); message('Disconnected. Reconnect and join a room, or log in again.'); });
 socket.connect();
}
$('form').onsubmit = async event => { event.preventDefault(); $('submit').disabled = true; try { const user = await api(signup ? '/api/signup' : '/api/login', { username:$('username').value, password:$('password').value }); $('password').value = ''; showGame(user); } catch (error) { message(error.message); } finally { $('submit').disabled = false; } };
$('logout').onclick = async () => { try { await api('/api/logout', {}); showAuth(); message('Logged out.'); } catch (error) { message(error.message); } };
$('join').onclick = () => {
 if (!socket?.connected) { message('Reconnecting. Press Join room when connected.'); socket?.connect(); return; }
 socket.timeout(5000).emit('join', $('room').value.trim(), (error, result) => { if (error) return message('Server did not respond. Try again.'); if (result.error) return message(result.error); joined = true; clearKeys(); $('roomInfo').textContent = 'Room: ' + result.room; message('Room joined. Share this site URL and room name with friends.'); });
};
const mapping = { w:'up', ArrowUp:'up', s:'down', ArrowDown:'down', a:'left', ArrowLeft:'left', d:'right', ArrowRight:'right' };
function clearKeys() { for (const key in keys) keys[key] = false; if (joined) socket?.emit('input', keys); }
window.addEventListener('keydown', event => { if (/INPUT|TEXTAREA/.test(event.target.tagName)) return; const key = mapping[event.key] || mapping[event.key.toLowerCase()]; if (key && joined) { event.preventDefault(); keys[key] = true; } });
window.addEventListener('keyup', event => { const key = mapping[event.key] || mapping[event.key.toLowerCase()]; if (key) keys[key] = false; });
window.addEventListener('blur', clearKeys); document.addEventListener('visibilitychange', clearKeys);
document.querySelectorAll('[data-key]').forEach(button => { button.onpointerdown = event => { event.preventDefault(); button.setPointerCapture(event.pointerId); keys[button.dataset.key] = true; }; for (const name of ['pointerup','pointercancel','lostpointercapture']) button.addEventListener(name, () => { keys[button.dataset.key] = false; }); });
setInterval(() => { if (joined && socket?.connected) socket.emit('input', keys); }, 50);
const ctx = $('arena').getContext('2d');
function render() { ctx.clearRect(0,0,800,500); ctx.strokeStyle = '#1c2938'; for (let x=0;x<800;x+=40) { ctx.beginPath(); ctx.moveTo(x,0); ctx.lineTo(x,500); ctx.stroke(); } for (let y=0;y<500;y+=40) { ctx.beginPath(); ctx.moveTo(0,y); ctx.lineTo(800,y); ctx.stroke(); } for (const p of state) { ctx.fillStyle = p.color; ctx.beginPath(); ctx.arc(p.x,p.y,11,0,Math.PI*2); ctx.fill(); if (p.id===self) { ctx.strokeStyle = '#fff'; ctx.lineWidth=2; ctx.stroke(); } ctx.fillStyle='#edf2f6'; ctx.textAlign='center'; ctx.font='13px system-ui'; ctx.fillText(p.username,p.x,Math.max(14,p.y-18)); } requestAnimationFrame(render); }
render(); api('/api/me').then(showGame).catch(() => message('Log in or create an account to play.'));
</script></body></html>`;
app.get('/', (req, res) => res.type('html').send(page));
app.use((err, req, res, next) => {
 if (res.headersSent) return next(err);
 if (err.status === 503) return res.status(503).json({ error: err.message });
 if (err.type === 'entity.parse.failed') return res.status(400).json({ error: 'Invalid JSON.' });
 if (err.type === 'entity.too.large') return res.status(413).json({ error: 'Request too large.' });
 console.error(err);
 res.status(500).json({ error: 'Server error. Try again.' });
});
server.listen(port, '0.0.0.0', () => console.log('BREACH listening on port ' + port));
