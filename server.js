import 'dotenv/config';
import express from 'express';
import session from 'express-session';
import mongoose from 'mongoose';
import bcrypt from 'bcryptjs';
import http from 'http';
import { Server } from 'socket.io';

const {
  PORT = 3000,
  MONGODB_URI,
  SESSION_SECRET = 'dev_secret_change_me'
} = process.env;

if (!MONGODB_URI) {
  console.error('Missing MONGODB_URI env var');
  process.exit(1);
}

await mongoose.connect(MONGODB_URI);

// ----- Models -----
const userSchema = new mongoose.Schema(
  {
    username: { type: String, unique: true, index: true },
    passwordHash: String,
    isAdmin: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now }
  },
  { minimize: false }
);

const txnSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, index: true },
    type: { type: String, enum: ['TOPUP', 'WITHDRAW'], required: true },
    amount: { type: Number, required: true },
    status: { type: String, enum: ['PENDING', 'APPROVED', 'REJECTED'], default: 'PENDING' },
    note: { type: String, default: '' },
    createdAt: { type: Date, default: Date.now }
  },
  { minimize: false }
);

const ticketSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, index: true },
    subject: { type: String, required: true },
    message: { type: String, required: true },
    status: { type: String, enum: ['OPEN', 'CLOSED'], default: 'OPEN' },
    createdAt: { type: Date, default: Date.now }
  },
  { minimize: false }
);

const User = mongoose.model('User', userSchema);
const Txn = mongoose.model('Txn', txnSchema);
const Ticket = mongoose.model('Ticket', ticketSchema);

// ----- App -----
const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: true, credentials: true } });

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    name: 'duel.sid',
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: 'lax',
      secure: false // Railway terminates TLS; keep false unless you add proxy+secure cookie handling
    }
  })
);

// Static
app.use(express.static('public'));

// ----- Helpers -----
function requireAuth(req, res, next) {
  if (!req.session?.userId) return res.status(401).json({ error: 'Unauthorized' });
  next();
}
async function requireAdmin(req, res, next) {
  if (!req.session?.userId) return res.status(401).json({ error: 'Unauthorized' });
  const me = await User.findById(req.session.userId).lean();
  if (!me?.isAdmin) return res.status(403).json({ error: 'Forbidden' });
  next();
}

// ----- Auth -----
app.post('/api/signup', async (req, res) => {
  try {
    const { username, password } = req.body;

    // username: 5-12 letters/numbers only
    if (!/^[a-zA-Z0-9]{5,12}$/.test(username || '')) {
      return res.status(400).json({ error: 'Username must be 5-12 characters (letters/numbers only).' });
    }

    // password: 5-12 any chars
    if (typeof password !== 'string' || password.length < 5 || password.length > 12) {
      return res.status(400).json({ error: 'Password must be 5-12 characters.' });
    }

    const passwordHash = await bcrypt.hash(password, 10);
    const created = await User.create({ username, passwordHash, isAdmin: false });

    req.session.userId = created._id.toString();
    req.session.username = created.username;

    return res.json({ ok: true });
  } catch (e) {
    if (String(e?.message || '').includes('duplicate key')) {
      return res.status(409).json({ error: 'Username already exists.' });
    }
    console.error(e);
    return res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/login', async (req, res) => {
  try {
    const { username, password } = req.body;
    const u = await User.findOne({ username }).lean();
    if (!u) return res.status(401).json({ error: 'Invalid username/password.' });

    const ok = await bcrypt.compare(password || '', u.passwordHash);
    if (!ok) return res.status(401).json({ error: 'Invalid username/password.' });

    req.session.userId = u._id.toString();
    req.session.username = u.username;

    return res.json({ ok: true, isAdmin: !!u.isAdmin });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: 'Server error' });
  }
});

app.post('/api/logout', (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get('/api/me', async (req, res) => {
  if (!req.session?.userId) return res.json({ authed: false });
  const me = await User.findById(req.session.userId).lean();
  return res.json({ authed: true, username: me?.username, isAdmin: !!me?.isAdmin });
});

// ----- Player requests (Topup / Withdraw) -----
app.post('/api/txns', requireAuth, async (req, res) => {
  const { type, amount, note = '' } = req.body;
  const amt = Number(amount);

  if (!['TOPUP', 'WITHDRAW'].includes(type)) return res.status(400).json({ error: 'Invalid type.' });
  if (!Number.isFinite(amt) || amt <= 0) return res.status(400).json({ error: 'Invalid amount.' });

  const doc = await Txn.create({
    userId: req.session.userId,
    type,
    amount: Math.floor(amt),
    note: String(note).slice(0, 140)
  });

  return res.json({ ok: true, txn: doc });
});

app.get('/api/txns', requireAuth, async (req, res) => {
  const rows = await Txn.find({ userId: req.session.userId }).sort({ createdAt: -1 }).lean();
  res.json({ ok: true, rows });
});

// ----- Support tickets -----
app.post('/api/tickets', requireAuth, async (req, res) => {
  const { subject, message } = req.body;
  if (!subject || !message) return res.status(400).json({ error: 'Missing fields.' });

  const doc = await Ticket.create({
    userId: req.session.userId,
    subject: String(subject).slice(0, 80),
    message: String(message).slice(0, 1000)
  });

  return res.json({ ok: true, ticket: doc });
});

app.get('/api/tickets', requireAuth, async (req, res) => {
  const rows = await Ticket.find({ userId: req.session.userId }).sort({ createdAt: -1 }).lean();
  res.json({ ok: true, rows });
});

// ----- Admin APIs -----
app.get('/api/admin/players', requireAdmin, async (req, res) => {
  const rows = await User.find({}, { username: 1, isAdmin: 1, createdAt: 1 }).sort({ createdAt: -1 }).lean();
  res.json({ ok: true, rows });
});

app.get('/api/admin/txns', requireAdmin, async (req, res) => {
  const rows = await Txn.find({}).sort({ createdAt: -1 }).lean();
  res.json({ ok: true, rows });
});

app.post('/api/admin/txns/:id', requireAdmin, async (req, res) => {
  const { status } = req.body;
  if (!['APPROVED', 'REJECTED'].includes(status)) return res.status(400).json({ error: 'Invalid status.' });

  const updated = await Txn.findByIdAndUpdate(req.params.id, { status }, { new: true }).lean();
  res.json({ ok: true, updated });
});

app.get('/api/admin/tickets', requireAdmin, async (req, res) => {
  const rows = await Ticket.find({}).sort({ createdAt: -1 }).lean();
  res.json({ ok: true, rows });
});

app.post('/api/admin/tickets/:id', requireAdmin, async (req, res) => {
  const { status } = req.body;
  if (!['OPEN', 'CLOSED'].includes(status)) return res.status(400).json({ error: 'Invalid status.' });

  const updated = await Ticket.findByIdAndUpdate(req.params.id, { status }, { new: true }).lean();
  res.json({ ok: true, updated });
});

// ----- Socket realtime presence + chat -----
const online = new Map(); // socketId -> { userId, username }

io.use((socket, next) => {
  // basic session-less auth: client passes username from /api/me check
  // (still OK for MVP). For stricter auth, wire real session middleware into socket.io.
  next();
});

io.on('connection', (socket) => {
  socket.on('hello', ({ username }) => {
    if (typeof username !== 'string' || !username.trim()) return;
    online.set(socket.id, { username: username.trim() });
    io.emit('presence', Array.from(online.values()));
  });

  socket.on('chat', (msg) => {
    const u = online.get(socket.id);
    if (!u) return;
    const text = String(msg || '').slice(0, 200);
    if (!text.trim()) return;
    io.emit('chat', { user: u.username, text, ts: Date.now() });
  });

  socket.on('speaking', (isSpeaking) => {
    const u = online.get(socket.id);
    if (!u) return;
    io.emit('speaking', { user: u.username, speaking: !!isSpeaking });
  });

  socket.on('disconnect', () => {
    online.delete(socket.id);
    io.emit('presence', Array.from(online.values()));
  });
});

server.listen(PORT, () => console.log(`Listening on :${PORT}`));
