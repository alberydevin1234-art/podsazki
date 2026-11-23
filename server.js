const express = require('express');
const multer = require('multer');
const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const PORT = process.env.PORT || 3000;
const DATA = process.env.DATA_DIR || path.join(__dirname, 'data');
const UPLOADS = path.join(DATA, 'uploads');
fs.mkdirSync(UPLOADS, { recursive: true });

const DB_FILE = path.join(DATA, 'db.json');
let db = fs.existsSync(DB_FILE) ? JSON.parse(fs.readFileSync(DB_FILE, 'utf8')) : { items: [] };
const save = () => fs.writeFileSync(DB_FILE, JSON.stringify(db));

// --- Учётные записи берутся из переменных окружения (пароли в код не пишем) ---
const users = [];
if (process.env.PUBLISHER_PASS)
  users.push({ u: (process.env.PUBLISHER_USER || 'nexus').toLowerCase(), p: process.env.PUBLISHER_PASS, role: 'publisher' });
if (process.env.OWNER_PASS)
  users.push({ u: (process.env.OWNER_USER || 'owner').toLowerCase(), p: process.env.OWNER_PASS, role: 'owner' });
if (!users.length) {
  console.error('Задайте переменную PUBLISHER_PASS (и по желанию OWNER_PASS). См. README.md');
  process.exit(1);
}

const SECRET = process.env.SECRET || crypto.randomBytes(32).toString('hex');
const h = (s) => crypto.createHash('sha256').update(String(s)).digest();
const same = (a, b) => crypto.timingSafeEqual(h(a), h(b));
const sign = (s) => crypto.createHmac('sha256', SECRET).update(s).digest('base64url');

function makeToken(u) {
  const body = Buffer.from(JSON.stringify({ u: u.u, role: u.role, exp: Date.now() + 7 * 864e5 })).toString('base64url');
  return body + '.' + sign(body);
}
function readToken(req) {
  const m = /(?:^|;\s*)auth=([^;]+)/.exec(req.headers.cookie || '');
  if (!m) return null;
  const [body, sig] = m[1].split('.');
  if (!body || !sig || !same(sig, sign(body))) return null;
  try {
    const d = JSON.parse(Buffer.from(body, 'base64url').toString());
    return d.exp > Date.now() ? d : null;
  } catch { return null; }
}
const need = (role) => (req, res, next) => {
  const t = readToken(req);
  if (!t || (role === 'owner' && t.role !== 'owner')) return res.status(403).json({ error: 'Нет доступа' });
  req.user = t; next();
};

// --- Защита от подбора пароля: 10 попыток за 15 минут с одного IP ---
const tries = new Map();
function limited(ip) {
  const now = Date.now();
  const a = (tries.get(ip) || []).filter((t) => now - t < 15 * 60e3);
  tries.set(ip, a);
  return a.length >= 10;
}

const ORGS = ['ФСБ', 'ФСИН', 'ППС', 'ГАИ', 'ЕСС'];
const ALLOWED = ['.pdf', '.doc', '.docx', '.xls', '.xlsx', '.ppt', '.pptx', '.txt', '.zip', '.rar', '.jpg', '.jpeg', '.png'];
const upload = multer({
  storage: multer.diskStorage({
    destination: UPLOADS,
    filename: (req, f, cb) => cb(null, crypto.randomBytes(12).toString('hex')),
  }),
  limits: { fileSize: 50 * 1024 * 1024 },
  fileFilter: (req, f, cb) => {
    const name = Buffer.from(f.originalname, 'latin1').toString('utf8');
    cb(null, ALLOWED.includes(path.extname(name).toLowerCase()));
  },
});

const app = express();
app.set('trust proxy', 1);
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

app.get('/api/me', (req, res) => {
  const t = readToken(req);
  res.json(t ? { user: t.u, role: t.role } : {});
});

app.post('/api/login', (req, res) => {
  if (limited(req.ip)) return res.status(429).json({ error: 'Слишком много попыток. Подождите 15 минут.' });
  const { login = '', password = '' } = req.body || {};
  const u = users.find((x) => x.u === String(login).trim().toLowerCase());
  if (!u || !same(u.p, password)) {
    tries.get(req.ip).push(Date.now());
    return res.status(401).json({ error: 'Неверный логин или пароль' });
  }
  res.setHeader('Set-Cookie',
    `auth=${makeToken(u)}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${7 * 86400}${req.secure ? '; Secure' : ''}`);
  res.json({ user: u.u, role: u.role });
});

app.post('/api/logout', (req, res) => {
  res.setHeader('Set-Cookie', 'auth=; HttpOnly; SameSite=Lax; Path=/; Max-Age=0');
  res.json({ ok: true });
});

app.get('/api/items', (req, res) => {
  res.json(db.items.map(({ stored, ...rest }) => rest).sort((a, b) => b.ts - a.ts));
});

app.post('/api/items', need('publisher'), upload.single('file'), (req, res) => {
  const { org, title = '', desc = '' } = req.body || {};
  if (!req.file) return res.status(400).json({ error: 'Файл не принят (проверьте тип и размер до 50 МБ)' });
  if (!ORGS.includes(org) || !title.trim()) {
    fs.unlink(req.file.path, () => {});
    return res.status(400).json({ error: 'Укажите организацию и название' });
  }
  const item = {
    id: crypto.randomBytes(6).toString('hex'),
    org, title: title.trim().slice(0, 200), desc: desc.trim().slice(0, 2000),
    fname: Buffer.from(req.file.originalname, 'latin1').toString('utf8'),
    stored: req.file.filename, size: req.file.size, downloads: 0, ts: Date.now(),
  };
  db.items.push(item); save();
  res.json({ ok: true });
});

app.delete('/api/items/:id', need('owner'), (req, res) => {
  const i = db.items.findIndex((x) => x.id === req.params.id);
  if (i < 0) return res.status(404).json({ error: 'Не найдено' });
  fs.unlink(path.join(UPLOADS, db.items[i].stored), () => {});
  db.items.splice(i, 1); save();
  res.json({ ok: true });
});

app.get('/download/:id', (req, res) => {
  const it = db.items.find((x) => x.id === req.params.id);
  if (!it) return res.status(404).send('Файл не найден');
  it.downloads++; save();
  res.download(path.join(UPLOADS, it.stored), it.fname);
});

app.listen(PORT, () => console.log('Сайт запущен: http://localhost:' + PORT));
