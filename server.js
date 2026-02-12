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
    archived: { type: Boolean, default: false },
    createdAt: { type: Date, default: Date.now }
  },
  { minimize: false }
);

// ticket now has threaded messages
const ticketSchema = new mongoose.Schema(
  {
    userId: { type: mongoose.Schema.Types.ObjectId, index: true },
    subject: { type: String, required: true },
    status: { type: String, enum: ["OPEN", "CLOSED"], default: "OPEN" },
    archived: { type: Boolean, default: false },
    messages: [
      {
        from: { type: String, required: true }, // username or "ADMIN"
        text: { type: String, required: true },
        ts: { type: Date, default: Date.now }
      }
    ],
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
function safeInt(n) {
  return Number.isFinite(n) ? Math.floor(n) : 0;
}
function isValidUsername(u) {
  return /^[a-zA-Z0-9]{5,12}$/.test(u || "");
}
function isValidPassword(p) {
  return typeof p === "string" && p.length >= 5 && p.length <= 12;
}

async function getMe(req) {
  if (!req.session?.userId) return null;
  return User.findById(req.session.userId).lean();
}

function requireAuth(req, res, next) {
  if (!req.session?.userId) return res.status(401).json({ error: "Unauthorized" });
  next();
}

async function requireAdmin(req, res, next) {
  const me = await getMe(req);
  if (!me) return res.status(401).json({ error: "Unauthorized" });
  if (!me.isAdmin) return res.status(403).json({ error: "Forbidden" });
  next();
}

function publicCredits(user) {
  // ✅ admin infinite credits
  if (user?.isAdmin) return 999999999;
  return safeInt(user?.credits);
}

// ----- Auth -----
app.post("/api/signup", async (req, res) => {
  try {
    const { username, password } = req.body;

    if (!isValidUsername(username)) {
      return res.status(400).json({ error: "Username must be 5-12 characters (letters/numbers only)." });
    }
    if (!isValidPassword(password)) {
      return res.status(400).json({ error: "Password must be 5-12 characters." });
    }

    const passwordHash = await bcrypt.hash(password, 10);

    const created = await User.create({
      username,
      passwordHash,
      isAdmin: false,
      credits: 0,
      avatar: "avatar1"
    });

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
  const me = await getMe(req);
  if (!me) return res.json({ authed: false });
  res.json({ authed: true, username: me.username, isAdmin: !!me.isAdmin });
});

app.get("/api/credits", requireAuth, async (req, res) => {
  const me = await getMe(req);
  if (!me) return res.status(401).json({ error: "Unauthorized" });

  // ensure defaults
  const avatar = me.avatar || "avatar1";
  const credits = publicCredits(me);

  if (!me.isAdmin) {
    // normalize stored credits only for non-admin
    if (!Number.isFinite(me.credits) || !me.avatar) {
      await User.updateOne({ _id: me._id }, { $set: { credits: safeInt(me.credits), avatar } });
    }
  } else {
    // admin: ensure avatar exists
    if (!me.avatar) await User.updateOne({ _id: me._id }, { $set: { avatar } });
  }

  res.json({ ok: true, username: me.username, credits, avatar, isAdmin: !!me.isAdmin });
});

app.get("/api/player/:username", requireAuth, async (req, res) => {
  const u = await User.findOne({ username: req.params.username }).lean();
  if (!u) return res.status(404).json({ error: "Player not found" });

  const credits = publicCredits(u);
  const avatar = u.avatar || "avatar1";

  if (!u.isAdmin) {
    if (!Number.isFinite(u.credits) || !u.avatar) {
      await User.updateOne({ username: u.username }, { $set: { credits: safeInt(u.credits), avatar } });
    }
  } else {
    if (!u.avatar) await User.updateOne({ username: u.username }, { $set: { avatar } });
  }

  res.json({ ok: true, username: u.username, credits, avatar, isAdmin: !!u.isAdmin });
});

app.post("/api/avatar", requireAuth, async (req, res) => {
  const { avatar } = req.body;
  const allowed = new Set(["avatar1", "avatar2", "avatar3", "avatar4", "avatar5", "avatar6"]);
  if (!allowed.has(avatar)) return res.status(400).json({ error: "Invalid avatar" });

  await User.findByIdAndUpdate(req.session.userId, { avatar });
  res.json({ ok: true });
});

// ----- Player Requests (Topup / Withdraw) -----
app.post("/api/txns", requireAuth, async (req, res) => {
  const { type, amount, note = "" } = req.body;
  const amt = Number(amount);

  if (!["TOPUP", "WITHDRAW"].includes(type)) return res.status(400).json({ error: "Invalid type." });
  if (!Number.isFinite(amt) || amt <= 0) return res.status(400).json({ error: "Invalid amount." });

  const doc = await Txn.create({
    userId: req.session.userId,
    type,
    amount: Math.floor(amt),
    note: String(note).slice(0, 140),
    archived: false
  });

  return res.json({ ok: true, txn: doc });
});

app.get("/api/txns", requireAuth, async (req, res) => {
  const rows = await Txn.find({ userId: req.session.userId, archived: false }).sort({ createdAt: -1 }).lean();
  res.json({ ok: true, rows });
});

// ----- Support Tickets (player) -----
app.post("/api/tickets", requireAuth, async (req, res) => {
  const me = await getMe(req);
  const { subject, message } = req.body;

  if (!subject || !message) return res.status(400).json({ error: "Missing fields." });

  const doc = await Ticket.create({
    userId: req.session.userId,
    subject: String(subject).slice(0, 80),
    status: "OPEN",
    archived: false,
    messages: [{ from: me.username, text: String(message).slice(0, 1000) }]
  });

  return res.json({ ok: true, ticket: doc });
});

app.get("/api/tickets", requireAuth, async (req, res) => {
  const rows = await Ticket.find({ userId: req.session.userId, archived: false }).sort({ createdAt: -1 }).lean();
  res.json({ ok: true, rows });
});

app.get("/api/tickets/:id", requireAuth, async (req, res) => {
  const me = await getMe(req);
  const t = await Ticket.findById(req.params.id).lean();
  if (!t) return res.status(404).json({ error: "Not found" });

  if (!me.isAdmin && String(t.userId) !== String(me._id)) {
    return res.status(403).json({ error: "Forbidden" });
  }

  res.json({ ok: true, ticket: t });
});

app.post("/api/tickets/:id/messages", requireAuth, async (req, res) => {
  const me = await getMe(req);
  const { text } = req.body;
  if (!text || !String(text).trim()) return res.status(400).json({ error: "Empty message" });

  const t = await Ticket.findById(req.params.id);
  if (!t) return res.status(404).json({ error: "Not found" });

  if (!me.isAdmin && String(t.userId) !== String(me._id)) {
    return res.status(403).json({ error: "Forbidden" });
  }

  if (t.status === "CLOSED") return res.status(400).json({ error: "Ticket closed" });

  t.messages.push({ from: me.isAdmin ? "ADMIN" : me.username, text: String(text).slice(0, 1000) });
  await t.save();

  res.json({ ok: true, ticket: t });
});

// ----- Admin APIs -----
app.get("/api/admin/players", requireAdmin, async (req, res) => {
  const rows = await User.find({}, { username: 1, isAdmin: 1, credits: 1, avatar: 1, createdAt: 1 })
    .sort({ createdAt: -1 })
    .lean();

  // return with public credits
  res.json({
    ok: true,
    rows: rows.map((u) => ({
      username: u.username,
      isAdmin: !!u.isAdmin,
      credits: u.isAdmin ? 999999999 : safeInt(u.credits),
      avatar: u.avatar || "avatar1",
      createdAt: u.createdAt
    }))
  });
});

app.get("/api/admin/txns", requireAdmin, async (req, res) => {
  const archived = req.query.archived === "1";
  const rows = await Txn.find({ archived }).sort({ createdAt: -1 }).lean();
  res.json({ ok: true, rows });
});

app.post("/api/admin/txns/:id", requireAdmin, async (req, res) => {
  const { status } = req.body;

  if (!["APPROVED", "REJECTED"].includes(status)) {
    return res.status(400).json({ error: "Invalid status." });
  }

  const txn = await Txn.findById(req.params.id);
  if (!txn) return res.status(404).json({ error: "Transaction not found." });

  // ✅ prevent double processing
  if (txn.status !== "PENDING") {
    return res.status(400).json({ error: "This request is already processed." });
  }

  if (status === "REJECTED") {
    txn.status = "REJECTED";
    await txn.save();
    return res.json({ ok: true, updated: txn });
  }

  const user = await User.findById(txn.userId);
  if (!user) return res.status(404).json({ error: "User not found." });

  // ✅ admin infinite credits: admin never changes credits
  if (user.isAdmin) {
    txn.status = "APPROVED";
    await txn.save();
    io.emit("credits:updated", { username: user.username, credits: 999999999 });
    return res.json({ ok: true, updated: txn, username: user.username, credits: 999999999 });
  }

  const currentCredits = safeInt(user.credits);
  const amount = safeInt(txn.amount);

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

  io.emit("credits:updated", { username: user.username, credits: newCredits });

  return res.json({ ok: true, updated: txn, username: user.username, credits: newCredits });
});

app.post("/api/admin/txns/:id/archive", requireAdmin, async (req, res) => {
  const { archived } = req.body;
  const tx = await Txn.findByIdAndUpdate(req.params.id, { archived: !!archived }, { new: true }).lean();
  if (!tx) return res.status(404).json({ error: "Not found" });
  res.json({ ok: true, txn: tx });
});

app.get("/api/admin/tickets", requireAdmin, async (req, res) => {
  const archived = req.query.archived === "1";
  const rows = await Ticket.find({ archived }).sort({ createdAt: -1 }).lean();
  res.json({ ok: true, rows });
});

app.post("/api/admin/tickets/:id/status", requireAdmin, async (req, res) => {
  const { status } = req.body;
  if (!["OPEN", "CLOSED"].includes(status)) return res.status(400).json({ error: "Invalid status" });

  const t = await Ticket.findByIdAndUpdate(req.params.id, { status }, { new: true }).lean();
  if (!t) return res.status(404).json({ error: "Not found" });
  res.json({ ok: true, ticket: t });
});

app.post("/api/admin/tickets/:id/archive", requireAdmin, async (req, res) => {
  const { archived } = req.body;
  const t = await Ticket.findByIdAndUpdate(req.params.id, { archived: !!archived }, { new: true }).lean();
  if (!t) return res.status(404).json({ error: "Not found" });
  res.json({ ok: true, ticket: t });
});

// ------------------ REALTIME: presence + seats + proposer + proposal + pot + emotes ------------------
const online = new Map(); // socketId -> { username, avatar, speaking }

// proposerUsername = whoever sat first
const room = {
  seat1: null,
  seat2: null,
  proposer: null, // ✅ whoever sat first
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
      proposer: room.proposer,
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
  room.proposer = null;
  room.proposal = null;
  room.pot = 0;
  room.settingsLocked = false;
}

async function getUser(username) {
  return User.findOne({ username }).lean();
}

async function setCredits(username, newCredits) {
  const u = await User.findOne({ username }).lean();
  if (!u) return;
  if (u.isAdmin) return; // ✅ admin never changes
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

  socket.on("takeSeat", ({ seat }) => {
    const u = online.get(socket.id);
    if (!u) return;

    // already seated anywhere
    if (room.seat1 === u.username || room.seat2 === u.username) return;

    if (seat === 1) {
      if (room.seat1) return;
      room.seat1 = u.username;
    } else if (seat === 2) {
      if (room.seat2) return;
      room.seat2 = u.username;
    } else return;

    // ✅ whoever sits first becomes proposer
    if (!room.proposer) room.proposer = u.username;

    // reset any pending proposal until both seated
    room.proposal = null;
    room.pot = 0;
    room.settingsLocked = false;

    io.emit("state", snapshot());
  });

  socket.on("leaveSeat", () => {
    const u = online.get(socket.id);
    if (!u) return;

    const wasSeated = (room.seat1 === u.username) || (room.seat2 === u.username);

    if (room.seat1 === u.username) room.seat1 = null;
    if (room.seat2 === u.username) room.seat2 = null;

    // if someone leaves, reset proposer logic cleanly
    if (wasSeated) {
      room.proposer = null;
      // if someone is still seated, they become proposer automatically
      if (room.seat1) room.proposer = room.seat1;
      else if (room.seat2) room.proposer = room.seat2;
    }

    room.proposal = null;
    room.pot = 0;
    room.settingsLocked = false;

    io.emit("state", snapshot());
  });

  // ✅ proposer is whoever sat first (room.proposer)
  socket.on("proposal:create", async ({ game, roundsKey, bet }) => {
    const u = online.get(socket.id);
    if (!u) return;

    // must be proposer
    if (room.proposer !== u.username) return;

    // must have both seats
    if (!room.seat1 || !room.seat2) return;

    if (room.settingsLocked) return;

    const allowedGames = new Set(["dice", "coin", "hl", "roulette", "rps", "ttt"]);
    const allowedRounds = new Set(["sd1", "bo3", "bo5", "rt3", "rt5"]);
    if (!allowedGames.has(game) || !allowedRounds.has(roundsKey)) return;

    const wager = Number(bet);
    if (!Number.isFinite(wager) || wager <= 0) return;

    const p1 = await getUser(room.seat1);
    const p2 = await getUser(room.seat2);
    if (!p1 || !p2) return;

    const c1 = publicCredits(p1);
    const c2 = publicCredits(p2);

    if (c1 < wager || c2 < wager) {
      socket.emit("proposal:error", { error: "One of the players has insufficient credits." });
      return;
    }

    room.proposal = { by: u.username, game, roundsKey, bet: Math.floor(wager), ts: Date.now() };
    room.pot = 0;
    room.settingsLocked = false;

    io.emit("state", snapshot());

    // send to opponent (the other seated)
    const opponent = room.seat1 === u.username ? room.seat2 : room.seat1;
    io.emit("proposal:incoming", { to: opponent, proposal: room.proposal });
  });

  socket.on("proposal:respond", async ({ accept }) => {
    const u = online.get(socket.id);
    if (!u) return;
    if (!room.proposal) return;
    if (room.settingsLocked) return;

    // only opponent can respond
    const opponent = room.seat1 === room.proposal.by ? room.seat2 : room.seat1;
    if (u.username !== opponent) return;

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

    const c1 = publicCredits(p1);
    const c2 = publicCredits(p2);

    if (c1 < wager || c2 < wager) {
      io.emit("proposal:result", { ok: false, accepted: false, error: "Insufficient credits." });
      return;
    }

    // debit (admin doesn't debit)
    if (!p1.isAdmin) await setCredits(room.seat1, c1 - wager);
    if (!p2.isAdmin) await setCredits(room.seat2, c2 - wager);

    room.pot = wager * 2;
    room.settingsLocked = true;

    io.emit("match:started", { proposal: room.proposal, pot: room.pot });
    io.emit("proposal:result", { ok: true, accepted: true, proposal: room.proposal, pot: room.pot });
    io.emit("state", snapshot());

    // update wallets (admin stays infinite)
    io.emit("credits:updated", { username: p1.username, credits: publicCredits(await getUser(p1.username)) });
    io.emit("credits:updated", { username: p2.username, credits: publicCredits(await getUser(p2.username)) });
  });

  socket.on("duel:emote", ({ emote }) => {
    const u = online.get(socket.id);
    if (!u) return;

    // only seated duel players
    if (u.username !== room.seat1 && u.username !== room.seat2) return;
    if (!room.settingsLocked) return;

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
      // if seated, clear match
      if (room.seat1 === u.username || room.seat2 === u.username) {
        clearMatch();
      }
    }

    io.emit("state", snapshot());
  });
});

server.listen(PORT, () => console.log(`Listening on :${PORT}`));
