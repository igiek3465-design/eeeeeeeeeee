const express = require('express');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const app = express();
app.use(express.json());

// Serve static files from the public folder (next to this file)
app.use(express.static(path.join(__dirname, 'public')));

const FILE = process.env.DATA_FILE || path.join(__dirname, 'data.json');
let db = { users: {}, sessions: {} };
try { db = JSON.parse(fs.readFileSync(FILE)); } catch {}
const save = () => fs.writeFileSync(FILE, JSON.stringify(db));
const hash = (p, s) => crypto.scryptSync(p, s, 32).toString('hex');

function startSession(res, name) {
  const token = crypto.randomBytes(24).toString('hex');
  db.sessions[token] = name; save();
  res.json({ token, name });
}
function auth(req, res, next) {
  const u = db.sessions[(req.headers.authorization || '').replace('Bearer ', '')];
  if (!u) return res.status(401).json({ error: 'Please sign in.' });
  req.user = u; next();
}

app.post('/api/signup', (req, res) => {
  const n = String(req.body.name || '').trim().toLowerCase(), p = String(req.body.password || '');
  if (!/^[a-z0-9_]{3,20}$/.test(n) || p.length < 6)
    return res.status(400).json({ error: 'Name: 3-20 letters or numbers. Password: at least 6 characters.' });
  if (db.users[n]) return res.status(400).json({ error: 'That name is taken. Pick another one.' });
  const salt = crypto.randomBytes(16).toString('hex');
  db.users[n] = { salt, hash: hash(p, salt), games: [] };
  startSession(res, n);
});

app.post('/api/signin', (req, res) => {
  const n = String(req.body.name || '').trim().toLowerCase(), p = String(req.body.password || '');
  const u = db.users[n];
  const ok = u && crypto.timingSafeEqual(Buffer.from(hash(p, u.salt)), Buffer.from(u.hash));
  if (!ok) return res.status(400).json({ error: 'Wrong name or password.' });
  startSession(res, n);
});

app.get('/api/games', auth, (req, res) => res.json(db.users[req.user].games.slice(-10).reverse()));

app.post('/api/games', auth, (req, res) => {
  const rounds = (Array.isArray(req.body.rounds) ? req.body.rounds : []).slice(0, 5).map(r => ({
    country: String(r.country||'').slice(0, 60), capital: String(r.capital||'').slice(0, 60),
    guess: String(r.guess||'').slice(0, 60), ok: !!r.ok, secs: +r.secs || 0
  }));
  const mode = ['map','capitals'].includes(req.body.mode) ? req.body.mode : 'map';
  db.users[req.user].games.push({ date: Date.now(), score: rounds.filter(r => r.ok).length, rounds, mode });
  save(); res.json({ ok: true });
});

// Fallback: always serve index.html for the homepage
app.get('/', (req, res) => {
  res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

const PORT = process.env.PORT || 3000;
app.listen(PORT, () => console.log('Running on port', PORT));
