const path = require('path');
const express = require('express');
const Database = require('better-sqlite3');
const bcrypt = require('bcryptjs');
const jwt = require('jsonwebtoken');

const PORT = 3000;
const JWT_SECRET = process.env.JWT_SECRET || 'kohi-dev-secret-change-me';
const JWT_EXPIRES_IN = '7d';
const BCRYPT_ROUNDS = 10;

const db = new Database(path.join(__dirname, 'kohi.db'));
db.pragma('journal_mode = WAL');
db.pragma('foreign_keys = ON');

const stmts = {
  findByEmail: db.prepare('SELECT id, name, email, password_hash, position FROM users WHERE email = ?'),
  findById: db.prepare('SELECT id, name, email, position FROM users WHERE id = ?'),
  maxPosition: db.prepare('SELECT COALESCE(MAX(position), 0) AS max_pos FROM users'),
  insertUser: db.prepare(
    'INSERT INTO users (name, email, password_hash, position) VALUES (?, ?, ?, ?)'
  ),
  countUsers: db.prepare('SELECT COUNT(*) AS total FROM users'),
};

const registerTx = db.transaction((name, email, passwordHash) => {
  if (stmts.findByEmail.get(email)) {
    const err = new Error('email_taken');
    err.code = 'EMAIL_TAKEN';
    throw err;
  }
  const position = stmts.maxPosition.get().max_pos + 1;
  const info = stmts.insertUser.run(name, email, passwordHash, position);
  return { id: info.lastInsertRowid, position };
});

const app = express();
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

function requireFields(body, fields) {
  const missing = fields.filter((f) => {
    const v = body?.[f];
    return v === undefined || v === null || (typeof v === 'string' && v.trim() === '');
  });
  return missing;
}

function authMiddleware(req, res, next) {
  const header = req.headers.authorization || '';
  const [scheme, token] = header.split(' ');
  if (scheme !== 'Bearer' || !token) {
    return res.status(401).json({ error: 'missing_or_invalid_token' });
  }
  try {
    const payload = jwt.verify(token, JWT_SECRET);
    req.userId = payload.sub;
    next();
  } catch {
    return res.status(401).json({ error: 'invalid_token' });
  }
}

app.post('/api/register', async (req, res) => {
  const missing = requireFields(req.body, ['name', 'email', 'password']);
  if (missing.length) {
    return res.status(400).json({ error: 'missing_fields', fields: missing });
  }
  const { name, email, password } = req.body;
  try {
    const passwordHash = await bcrypt.hash(password, BCRYPT_ROUNDS);
    const { id, position } = registerTx(name.trim(), email.trim().toLowerCase(), passwordHash);
    return res.status(201).json({ ok: true, id, position });
  } catch (err) {
    if (err.code === 'EMAIL_TAKEN' || err.code === 'SQLITE_CONSTRAINT_UNIQUE') {
      return res.status(409).json({ error: 'email_already_registered' });
    }
    console.error('register error:', err);
    return res.status(500).json({ error: 'internal_error' });
  }
});

app.post('/api/login', async (req, res) => {
  const missing = requireFields(req.body, ['email', 'password']);
  if (missing.length) {
    return res.status(400).json({ error: 'missing_fields', fields: missing });
  }
  const { email, password } = req.body;
  const user = stmts.findByEmail.get(email.trim().toLowerCase());
  if (!user) {
    return res.status(401).json({ error: 'invalid_credentials' });
  }
  const ok = await bcrypt.compare(password, user.password_hash);
  if (!ok) {
    return res.status(401).json({ error: 'invalid_credentials' });
  }
  const token = jwt.sign({ sub: user.id, email: user.email }, JWT_SECRET, {
    expiresIn: JWT_EXPIRES_IN,
  });
  return res.json({ ok: true, token });
});

app.get('/api/me', authMiddleware, (req, res) => {
  const user = stmts.findById.get(req.userId);
  if (!user) {
    return res.status(401).json({ error: 'user_not_found' });
  }
  const total = stmts.countUsers.get().total;
  return res.json({
    id: user.id,
    name: user.name,
    email: user.email,
    position: user.position,
    total,
  });
});

app.listen(PORT, () => {
  console.log(`Kōhi backend listening on http://localhost:${PORT}`);
});
