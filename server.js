import "dotenv/config";
import express from "express";
import session from "express-session";
import mongoose from "mongoose";
import bcrypt from "bcryptjs";
import http from "http";
import { Server } from "socket.io";

const { PORT = 3000, MONGODB_URI, SESSION_SECRET = "dev_secret_change_me" } = process.env;

if (!MONGODB_URI) {
  console.error("Missing MONGODB_URI env var");
  process.exit(1);
}

await mongoose.connect(MONGODB_URI);

// ----- Models -----
const userSchema = new mongoose.Schema(
  {
    username: { type: String, unique: true, index: true },
    passwordHash: String,
    isAdmin: { type: Boolean, default: false },
    credits: { type: Number, default: 0 },
    avatar: { type: String, default: "avatar1" },
    createdAt: { type: Date, default: Date.now }
  },
  { minimize: false }
);

const txnSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, index: true },
    type: { type: String, enum: ["TOPUP", "WITHDRAW"], required: true },
    amount: { type: Number, required: true },
    status: { type: String, enum: ["PENDING", "APPROVED", "REJECTED"], default: "PENDING" },
    note: { type: String, default: "" },
    createdAt: { type: Date, default: Date.now }
  },
  { minimize: false }
);

const ticketSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, index: true },
    subject: { type: String, required: true },
    message: { type: String, required: true },
    status: { type: String, enum: ["OPEN", "CLOSED"], default: "OPEN" },
    createdAt: { type: Date, default: Date.now }
  },
  { minimize: false }
);

const User = mongoose.model("User", userSchema);
const Txn = mongoose.model("Txn", txnSchema);
const Ticket = mongoose.model("Ticket", ticketSchema);

// ----- App -----
const app = express();
const server = http.createServer(app);
const io = new Server(server, { cors: { origin: true, credentials: true } });

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

app.use(
  session({
    name: "duel.sid",
    secret: SESSION_SECRET,
    resave: false,
    saveUninitialized: false,
    cookie: {
      httpOnly: true,
      sameSite: "lax",
      secure: false
    }
  })
);

app.use(express.static("public"));

// ----- Helpers -----
function requireAuth(req, res, next) {
  if (!req.session?.userId) return res.status(401).json({ error: "Unauthorized" });
  next();
}

async function requireAdmin(req, res, next) {
  if (!req.session?.userId) return res.status(401).json({ error: "Unauthorized" });
  const me = await User.findById(req.session.userId).lean();
  if (!me?.isAdmin) return res.status(403).json({ error: "Forbidden" });
  next();
}

function safeCredits(n) {
  return Number.isFinite(n) ? Math.floor(n) : 0;
}

// ----- Auth -----
app.post("/api/signup", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!/^[a-zA-Z0-9]{5,12}$/.test(username || "")) {
      return res.status(400).json({ error: "Username must be 5-12 characters (letters/numbers only)." });
    }
    if (typeof password !== "string" || password.length < 5 || password.length > 12) {
      return res.status(400).json({ error: "Password must be 5-12 characters." });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    // starter credits (change if you want)
    const created = await User.create({ username, passwordHash, isAdmin: false, credits: 1000, avatar: "avatar1" });

    req.session.userId = created._id.toString();
    req.session.username = created.username;

    return res.json({ ok: true });
  } catch (e) {
    if (String(e?.message || "").includes("duplicate key")) {
      return res.status(409).json({ error: "Username already exists." });
    }
    console.error(e);
    return res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/login", async (req, res) => {
  try {
    const { username, password } = req.body;
    const u = await User.findOne({ username }).lean();
    if (!u) return res.status(401).json({ error: "Invalid username/password." });

    const ok = await bcrypt.compare(password || "", u.passwordHash);
    if (!ok) return res.status(401).json({ error: "Invalid username/password." });

    req.session.userId = u._id.toString();
    req.session.username = u.username;

    return res.json({ ok: true, isAdmin: !!u.isAdmin });
  } catch (e) {
    console.error(e);
    return res.status(500).json({ error: "Server error" });
  }
});

app.post("/api/logout", (req, res) => {
  req.session.destroy(() => res.json({ ok: true }));
});

app.get("/api/me", async (req, res) => {
  if (!req.session?.userId) return res.json({ authed: false });
  const me = await User.findById(req.session.userId).lean();
  return res.json({
    authed: true,
    username: me?.username,
    isAdmin: !!me?.isAdmin
  });
});

// ✅ Credits always safe + auto-fix old users
app.get("/api/credits", requireAuth, async (req, res) => {
  const me = await User.findById(req.session.userId).lean();
  if (!me) return res.status(401).json({ error: "Unauthorized" });

  const credits = safeCredits(me.credits);
  const avatar = me.avatar || "avatar1";

  if (!Number.isFinite(me.credits) || !me.avatar) {
    await User.updateOne({ _id: me._id }, { $set: { credits, avatar } });
  }

  res.json({
    ok: true,
    username: me.username,
    credits,
    avatar,
    isAdmin: !!me.isAdmin
  });
});

// ✅ Authenticated player lookup (shows credits)
app.get("/api/player/:username", requireAuth, async (req, res) => {
  const u = await User.findOne({ username: req.params.username }).lean();
  if (!u) return res.status(404).json({ error: "Player not found" });

  const credits = safeCredits(u.credits);
  const avatar = u.avatar || "avatar1";

  if (!Number.isFinite(u.credits) || !u.avatar) {
    await User.updateOne({ username: u.username }, { $set: { credits, avatar } });
  }

  res.json({ ok: true, username: u.username, credits, avatar });
});

app.post("/api/avatar", requireAuth, async (req, res) => {
  const { avatar } = req.body;
  const allowed = new Set(["avatar1", "avatar2", "avatar3", "avatar4", "avatar5", "avatar6"]);
  if (!allowed.has(avatar)) return res.status(400).json({ error: "Invalid avatar" });

  await User.findByIdAndUpdate(req.session.userId, { avatar });
  res.json({ ok: true });
});

// ----- Player requests (Topup / Withdraw) -----
app.post("/api/txns", requireAuth, async (req, res) => {
  const { type, amount, note = "" } = req.body;
  const amt = Number(amount);

  if (!["TOPUP", "WITHDRAW"].includes(type)) return res.status(400).json({ error: "Invalid type." });
  if (!Number.isFinite(amt) || amt <= 0) return res.status(400).json({ error: "Invalid amount." });

  const doc = await Txn.create({
    userId: req.session.userId,
    type,
    amount: Math.floor(amt),
    note: String(note).slice(0, 140)
  });

  return res.json({ ok: true, txn: doc });
});

app.get("/api/txns", requireAuth, async (req, res) => {
  const rows = await Txn.find({ userId: req.session.userId }).sort({ createdAt: -1 }).lean();
  res.json({ ok: true, rows });
});

// ----- Support tickets -----
app.post("/api/tickets", requireAuth, async (req, res) => {
  const { subject, message } = req.body;
  if (!subject || !message) return res.status(400).json({ error: "Missing fields." });

  const doc = await Ticket.create({
    userId: req.session.userId,
    subject: String(subject).slice(0, 80),
    message: String(message).slice(0, 1000)
  });

  return res.json({ ok: true, ticket: doc });
});

app.get("/api/tickets", requireAuth, async (req, res) => {
  const rows = await Ticket.find({ userId: req.session.userId }).sort({ createdAt: -1 }).lean();
  res.json({ ok: true, rows });
});

// ----- Admin APIs -----
app.get("/api/admin/players", requireAdmin, async (req, res) => {
  const rows = await User.find({}, { username: 1, isAdmin: 1, credits: 1, avatar: 1, createdAt: 1 })
    .sort({ createdAt: -1 })
    .lean();
  res.json({ ok: true, rows });
});

app.get("/api/admin/user/:username", requireAdmin, async (req, res) => {
  const u = await User.findOne({ username: req.params.username }).lean();
  if (!u) return res.status(404).json({ error: "Not found" });
  res.json({
    ok: true,
    username: u.username,
    credits: safeCredits(u.credits),
    avatar: u.avatar || "avatar1",
    isAdmin: !!u.isAdmin
  });
});

app.get("/api/admin/txns", requireAdmin, async (req, res) => {
  const rows = await Txn.find({}).sort({ createdAt: -1 }).lean();
  res.json({ ok: true, rows });
});

// ✅ IMPORTANT FIX: approving actually updates user credits
app.post("/api/admin/txns/:id", requireAdmin, async (req, res) => {
  const { status } = req.body;
  if (!["APPROVED", "REJECTED"].includes(status)) {
    return res.status(400).json({ error: "Invalid status." });
  }

  const txn = await Txn.findById(req.params.id);
  if (!txn) return res.status(404).json({ error: "Transaction not found." });

  // prevent double-processing
  if (txn.status !== "PENDING") {
    return res.status(400).json({ error: "This request is already processed." });
  }

  // If rejected: just mark rejected
  if (status === "REJECTED") {
    txn.status = "REJECTED";
    await txn.save();
    return res.json({ ok: true, updated: txn });
  }

  // APPROVED: update player's credits
  const user = await User.findById(txn.userId);
  if (!user) return res.status(404).json({ error: "User not found." });

  const currentCredits = safeCredits(user.credits);
  const amount = safeCredits(txn.amount);

  let newCredits = currentCredits;

  if (txn.type === "TOPUP") {
    newCredits = currentCredits + amount;
  } else if (txn.type === "WITHDRAW") {
    if (currentCredits < amount) {
      return res.status(400).json({ error: "Insufficient credits to approve withdrawal." });
    }
    newCredits = currentCredits - amount;
  } else {
    return res.status(400).json({ error: "Invalid transaction type." });
  }

  user.credits = newCredits;
  await user.save();

  txn.status = "APPROVED";
  await txn.save();

  // ✅ realtime notify so the player panel updates instantly
  io.emit("credits:updated", { username: user.username, credits: newCredits });

  return res.json({ ok: true, updated: txn, username: user.username, credits: newCredits });
});

app.get("/api/admin/tickets", requireAdmin, async (req, res) => {
  const rows = await Ticket.find({}).sort({ createdAt: -1 }).lean();
  res.json({ ok: true, rows });
});

app.post("/api/admin/tickets/:id", requireAdmin, async (req, res) => {
  const { status } = req.body;
  if (!["OPEN", "CLOSED"].includes(status)) return res.status(400).json({ error: "Invalid status." });

  const updated = await Ticket.findByIdAndUpdate(req.params.id, { status }, { new: true }).lean();
  res.json({ ok: true, updated });
});

// ------------------ REALTIME: presence + seats + proposal + pot + emotes ------------------
const online = new Map(); // socketId -> { username, avatar, speaking }
const room = {
  seat1: null,
  seat2: null,
  proposal: null, // { by, game, roundsKey, bet, ts }
  pot: 0,
  settingsLocked: false
};

function snapshot() {
  const players = Array.from(online.values()).map((p) => ({
    username: p.username,
    avatar: p.avatar || "avatar1",
    seat: room.seat1 === p.username ? 1 : room.seat2 === p.username ? 2 : 0,
    speaking: !!p.speaking
  }));
  return {
    room: {
      seat1: room.seat1,
      seat2: room.seat2,
      proposal: room.proposal,
      pot: room.pot,
      settingsLocked: room.settingsLocked
    },
    players
  };
}

function clearMatch() {
  room.seat1 = null;
  room.seat2 = null;
  room.proposal = null;
  room.pot = 0;
  room.settingsLocked = false;
}

async function getUser(username) {
  return User.findOne({ username }).lean();
}

async function setCredits(username, newCredits) {
  await User.updateOne({ username }, { $set: { credits: Math.max(0, Math.floor(newCredits)) } });
}

io.on("connection", (socket) => {
  socket.on("hello", async ({ username }) => {
    try {
      if (typeof username !== "string" || !username.trim()) return;
      const u = await getUser(username.trim());
      if (!u) return;

      online.set(socket.id, { username: u.username, avatar: u.avatar || "avatar1", speaking: false });
      io.emit("state", snapshot());
    } catch (e) {
      console.error(e);
    }
  });

  socket.on("chat", (msg) => {
    const u = online.get(socket.id);
    if (!u) return;
    const text = String(msg || "").slice(0, 200);
    if (!text.trim()) return;
    io.emit("chat", { user: u.username, text, ts: Date.now() });
  });

  socket.on("speaking", (isSpeaking) => {
    const u = online.get(socket.id);
    if (!u) return;
    u.speaking = !!isSpeaking;
    io.emit("state", snapshot());
  });

  // Seat: 1 seat only, server enforced
  socket.on("takeSeat", ({ seat }) => {
    const u = online.get(socket.id);
    if (!u) return;

    if (room.seat1 === u.username || room.seat2 === u.username) return;

    if (seat === 1) {
      if (room.seat1) return;
      room.seat1 = u.username;
    } else if (seat === 2) {
      if (room.seat2) return;
      room.seat2 = u.username;
    } else return;

    room.proposal = null;
    room.pot = 0;
    room.settingsLocked = false;

    io.emit("state", snapshot());
  });

  socket.on("leaveSeat", () => {
    const u = online.get(socket.id);
    if (!u) return;

    if (room.seat1 === u.username) room.seat1 = null;
    if (room.seat2 === u.username) room.seat2 = null;

    room.proposal = null;
    room.pot = 0;
    room.settingsLocked = false;

    io.emit("state", snapshot());
  });

  socket.on("proposal:create", async ({ game, roundsKey, bet }) => {
    const u = online.get(socket.id);
    if (!u) return;
    if (room.seat1 !== u.username) return;
    if (!room.seat2) return;
    if (room.settingsLocked) return;

    const allowedGames = new Set(["dice", "coin", "hl", "roulette", "rps", "ttt"]);
    const allowedRounds = new Set(["sd1", "bo3", "bo5", "rt3", "rt5"]);
    if (!allowedGames.has(game) || !allowedRounds.has(roundsKey)) return;

    const wager = Number(bet);
    if (!Number.isFinite(wager) || wager <= 0) return;

    const p1 = await getUser(room.seat1);
    const p2 = await getUser(room.seat2);
    if (!p1 || !p2) return;

    if (safeCredits(p1.credits) < wager || safeCredits(p2.credits) < wager) {
      socket.emit("proposal:error", { error: "One of the players has insufficient credits." });
      return;
    }

    room.proposal = { by: u.username, game, roundsKey, bet: Math.floor(wager), ts: Date.now() };
    room.pot = 0;
    room.settingsLocked = false;

    io.emit("state", snapshot());
    io.emit("proposal:incoming", { to: room.seat2, proposal: room.proposal });
  });

  socket.on("proposal:respond", async ({ accept }) => {
    const u = online.get(socket.id);
    if (!u) return;
    if (!room.proposal) return;
    if (u.username !== room.seat2) return;
    if (room.settingsLocked) return;

    if (!accept) {
      room.proposal = null;
      room.pot = 0;
      room.settingsLocked = false;
      io.emit("state", snapshot());
      io.emit("proposal:result", { ok: true, accepted: false });
      return;
    }

    const wager = room.proposal.bet;
    const p1 = await getUser(room.seat1);
    const p2 = await getUser(room.seat2);
    if (!p1 || !p2) return;

    const c1 = safeCredits(p1.credits);
    const c2 = safeCredits(p2.credits);

    if (c1 < wager || c2 < wager) {
      io.emit("proposal:result", { ok: false, accepted: false, error: "Insufficient credits." });
      return;
    }

    await setCredits(room.seat1, c1 - wager);
    await setCredits(room.seat2, c2 - wager);

    room.pot = wager * 2;
    room.settingsLocked = true;

    io.emit("match:started", { proposal: room.proposal, pot: room.pot });
    io.emit("proposal:result", { ok: true, accepted: true, proposal: room.proposal, pot: room.pot });
    io.emit("state", snapshot());
  });

  socket.on("duel:emote", ({ emote }) => {
    const u = online.get(socket.id);
    if (!u) return;
    if (u.username !== room.seat1 && u.username !== room.seat2) return;

    const allowed = new Set(["😈", "😂", "🔥", "💀", "😤", "😎"]);
    if (!allowed.has(emote)) return;

    io.emit("duel:emote", { from: u.username, emote, ts: Date.now() });
  });

  socket.on("match:ended", () => {
    clearMatch();
    io.emit("state", snapshot());
  });

  socket.on("disconnect", () => {
    const u = online.get(socket.id);
    online.delete(socket.id);

    if (u) {
      if (room.seat1 === u.username || room.seat2 === u.username) {
        clearMatch();
      }
    }

    io.emit("state", snapshot());
  });
});

server.listen(PORT, () => console.log(`Listening on :${PORT}`));
