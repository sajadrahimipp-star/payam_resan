const path = require("path");
const http = require("http");
const express = require("express");
const cookieSession = require("cookie-session");
const { DatabaseSync } = require("node:sqlite");
const bcrypt = require("bcryptjs");
const helmet = require("helmet");
const { rateLimit } = require("express-rate-limit");
const { Server } = require("socket.io");

const PORT = Number(process.env.PORT || 3000);
const SESSION_SECRET = process.env.SESSION_SECRET || "change-this-secret-before-deploying";
const isProduction = process.env.NODE_ENV === "production";

if (isProduction && SESSION_SECRET === "change-this-secret-before-deploying") {
  throw new Error("Set a strong SESSION_SECRET environment variable before production use.");
}

const app = express();
const server = http.createServer(app);
const io = new Server(server);
const db = new DatabaseSync(path.join(__dirname, "nova.sqlite"));
db.exec("PRAGMA journal_mode = WAL; PRAGMA foreign_keys = ON;");

db.exec(`
  CREATE TABLE IF NOT EXISTS users (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    username TEXT NOT NULL UNIQUE COLLATE NOCASE,
    display_name TEXT NOT NULL,
    password_hash TEXT NOT NULL,
    bio TEXT DEFAULT '',
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    last_seen TEXT DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS contacts (
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    contact_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    created_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (user_id, contact_id),
    CHECK (user_id != contact_id)
  );

  CREATE TABLE IF NOT EXISTS chats (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    type TEXT NOT NULL CHECK (type IN ('private', 'group', 'channel')),
    title TEXT,
    description TEXT DEFAULT '',
    created_by INTEGER REFERENCES users(id) ON DELETE SET NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE TABLE IF NOT EXISTS chat_members (
    chat_id INTEGER NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
    user_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    role TEXT NOT NULL DEFAULT 'member' CHECK (role IN ('owner', 'admin', 'member')),
    last_read_id INTEGER DEFAULT 0,
    joined_at TEXT NOT NULL DEFAULT (datetime('now')),
    PRIMARY KEY (chat_id, user_id)
  );

  CREATE TABLE IF NOT EXISTS messages (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    chat_id INTEGER NOT NULL REFERENCES chats(id) ON DELETE CASCADE,
    sender_id INTEGER NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    body TEXT NOT NULL,
    created_at TEXT NOT NULL DEFAULT (datetime('now'))
  );

  CREATE INDEX IF NOT EXISTS messages_chat_idx ON messages(chat_id, id);
  CREATE INDEX IF NOT EXISTS chat_members_user_idx ON chat_members(user_id);
  CREATE INDEX IF NOT EXISTS contacts_user_idx ON contacts(user_id);
`);

// Migrate old private messages if any exist from previous schema
try {
  const hasOld = db.prepare("SELECT name FROM sqlite_master WHERE type='table' AND name='messages'").get();
  // Already handled by new schema; old data may be lost on schema change — acceptable for this upgrade
} catch (_) {}

const sessionMiddleware = cookieSession({
  name: "nova-session",
  keys: [SESSION_SECRET],
  httpOnly: true,
  sameSite: "lax",
  secure: isProduction,
  maxAge: 1000 * 60 * 60 * 24 * 7
});

app.use(helmet({
  contentSecurityPolicy: {
    directives: {
      defaultSrc: ["'self'"],
      scriptSrc: ["'self'"],
      styleSrc: ["'self'"],
      imgSrc: ["'self'", "data:"],
      connectSrc: ["'self'", "ws:", "wss:"]
    }
  }
}));
app.use(express.json({ limit: "30kb" }));
app.use(sessionMiddleware);
app.use(express.static(path.join(__dirname, "public")));

const authLimiter = rateLimit({
  windowMs: 15 * 60 * 1000,
  limit: 40,
  standardHeaders: "draft-7",
  legacyHeaders: false,
  message: { error: "تعداد تلاش‌ها زیاد است. کمی بعد دوباره امتحان کن." }
});

const onlineUsers = new Map(); // userId -> Set(socketId)

const userById = db.prepare("SELECT id, username, display_name, bio, last_seen FROM users WHERE id = ?");
const safeUser = row => row && ({
  id: row.id,
  username: row.username,
  displayName: row.display_name,
  bio: row.bio || "",
  lastSeen: row.last_seen
});

function requireAuth(req, res, next) {
  if (!req.session.userId) return res.status(401).json({ error: "ابتدا وارد حساب شو." });
  next();
}

function isMember(chatId, userId) {
  return !!db.prepare("SELECT 1 FROM chat_members WHERE chat_id = ? AND user_id = ?").get(chatId, userId);
}

function canPost(chatId, userId) {
  const chat = db.prepare("SELECT type FROM chats WHERE id = ?").get(chatId);
  if (!chat) return false;
  const member = db.prepare("SELECT role FROM chat_members WHERE chat_id = ? AND user_id = ?").get(chatId, userId);
  if (!member) return false;
  if (chat.type === "channel") return member.role === "owner" || member.role === "admin";
  return true;
}

// ---------- Auth ----------
app.post("/api/register", authLimiter, async (req, res) => {
  const username = String(req.body.username || "").trim().toLowerCase();
  const displayName = String(req.body.displayName || "").trim();
  const password = String(req.body.password || "");

  if (!/^[a-z0-9_]{3,20}$/.test(username)) {
    return res.status(400).json({ error: "نام کاربری باید ۳ تا ۲۰ حرف انگلیسی، عدد یا زیرخط باشد." });
  }
  if (displayName.length < 2 || displayName.length > 40) {
    return res.status(400).json({ error: "نام نمایشی باید بین ۲ تا ۴۰ کاراکتر باشد." });
  }
  if (password.length < 8 || password.length > 72) {
    return res.status(400).json({ error: "رمز عبور باید حداقل ۸ کاراکتر باشد." });
  }

  try {
    const hash = await bcrypt.hash(password, 12);
    const result = db.prepare(
      "INSERT INTO users (username, display_name, password_hash) VALUES (?, ?, ?)"
    ).run(username, displayName, hash);
    req.session.userId = Number(result.lastInsertRowid);
    res.status(201).json({ user: safeUser(userById.get(req.session.userId)) });
  } catch (err) {
    if (String(err.code).includes("SQLITE_CONSTRAINT")) {
      return res.status(409).json({ error: "این نام کاربری قبلاً ثبت شده است." });
    }
    console.error(err);
    res.status(500).json({ error: "خطای داخلی سرور." });
  }
});

app.post("/api/login", authLimiter, async (req, res) => {
  const username = String(req.body.username || "").trim().toLowerCase();
  const password = String(req.body.password || "");
  const row = db.prepare("SELECT * FROM users WHERE username = ?").get(username);
  if (!row || !(await bcrypt.compare(password, row.password_hash))) {
    return res.status(401).json({ error: "نام کاربری یا رمز عبور درست نیست." });
  }
  req.session.userId = row.id;
  db.prepare("UPDATE users SET last_seen = datetime('now') WHERE id = ?").run(row.id);
  res.json({ user: safeUser(row) });
});

app.post("/api/logout", requireAuth, (req, res) => {
  const userId = req.session.userId;
  db.prepare("UPDATE users SET last_seen = datetime('now') WHERE id = ?").run(userId);
  req.session = null;
  res.clearCookie("nova-session");
  res.json({ ok: true, userId });
});

app.get("/api/me", (req, res) => {
  if (!req.session.userId) return res.json({ user: null });
  res.json({ user: safeUser(userById.get(req.session.userId)) });
});

// ---------- Users & Contacts ----------
app.get("/api/users/search", requireAuth, (req, res) => {
  const q = String(req.query.q || "").trim().toLowerCase();
  if (q.length < 1) return res.json({ users: [] });
  const rows = db.prepare(`
    SELECT id, username, display_name, bio FROM users
    WHERE id != ? AND (username LIKE ? OR display_name LIKE ?)
    ORDER BY display_name COLLATE NOCASE LIMIT 30
  `).all(req.session.userId, `%${q}%`, `%${q}%`);
  const contactIds = new Set(
    db.prepare("SELECT contact_id FROM contacts WHERE user_id = ?").all(req.session.userId).map(r => r.contact_id)
  );
  res.json({
    users: rows.map(u => ({
      ...safeUser(u),
      online: onlineUsers.has(u.id),
      isContact: contactIds.has(u.id)
    }))
  });
});

app.get("/api/contacts", requireAuth, (req, res) => {
  const rows = db.prepare(`
    SELECT u.id, u.username, u.display_name, u.bio, u.last_seen
    FROM contacts c JOIN users u ON u.id = c.contact_id
    WHERE c.user_id = ?
    ORDER BY u.display_name COLLATE NOCASE
  `).all(req.session.userId);
  res.json({
    contacts: rows.map(u => ({
      ...safeUser(u),
      online: onlineUsers.has(u.id)
    }))
  });
});

app.post("/api/contacts", requireAuth, (req, res) => {
  const contactId = Number(req.body.contactId);
  if (!Number.isSafeInteger(contactId) || contactId < 1 || contactId === req.session.userId) {
    return res.status(400).json({ error: "شناسه مخاطب نامعتبر است." });
  }
  if (!userById.get(contactId)) return res.status(404).json({ error: "کاربر پیدا نشد." });
  try {
    db.prepare("INSERT OR IGNORE INTO contacts (user_id, contact_id) VALUES (?, ?)").run(req.session.userId, contactId);
    res.json({ ok: true });
  } catch (err) {
    console.error(err);
    res.status(500).json({ error: "خطا در افزودن مخاطب." });
  }
});

app.delete("/api/contacts/:id", requireAuth, (req, res) => {
  const contactId = Number(req.params.id);
  db.prepare("DELETE FROM contacts WHERE user_id = ? AND contact_id = ?").run(req.session.userId, contactId);
  res.json({ ok: true });
});

// ---------- Chats ----------
function getChatPreview(chatId, currentUserId) {
  const chat = db.prepare("SELECT * FROM chats WHERE id = ?").get(chatId);
  if (!chat) return null;

  const memberCount = db.prepare("SELECT COUNT(*) AS c FROM chat_members WHERE chat_id = ?").get(chatId).c;
  const lastMsg = db.prepare(`
    SELECT m.id, m.body, m.created_at, m.sender_id, u.display_name
    FROM messages m JOIN users u ON u.id = m.sender_id
    WHERE m.chat_id = ? ORDER BY m.id DESC LIMIT 1
  `).get(chatId);

  const myMember = db.prepare("SELECT last_read_id, role FROM chat_members WHERE chat_id = ? AND user_id = ?")
    .get(chatId, currentUserId);
  const unread = lastMsg
    ? db.prepare("SELECT COUNT(*) AS c FROM messages WHERE chat_id = ? AND id > ? AND sender_id != ?")
        .get(chatId, myMember?.last_read_id || 0, currentUserId).c
    : 0;

  let title = chat.title;
  let peer = null;
  if (chat.type === "private") {
    const other = db.prepare(`
      SELECT u.id, u.username, u.display_name, u.bio FROM chat_members cm
      JOIN users u ON u.id = cm.user_id
      WHERE cm.chat_id = ? AND cm.user_id != ?
    `).get(chatId, currentUserId);
    if (other) {
      title = other.display_name;
      peer = { ...safeUser(other), online: onlineUsers.has(other.id) };
    }
  }

  return {
    id: chat.id,
    type: chat.type,
    title: title || "بدون عنوان",
    description: chat.description || "",
    memberCount,
    role: myMember?.role || "member",
    peer,
    lastMessage: lastMsg ? {
      id: lastMsg.id,
      body: lastMsg.body,
      createdAt: lastMsg.created_at,
      senderId: lastMsg.sender_id,
      senderName: lastMsg.display_name
    } : null,
    unread
  };
}

app.get("/api/chats", requireAuth, (req, res) => {
  const chatIds = db.prepare("SELECT chat_id FROM chat_members WHERE user_id = ?").all(req.session.userId).map(r => r.chat_id);
  const chats = chatIds.map(id => getChatPreview(id, req.session.userId)).filter(Boolean);
  chats.sort((a, b) => {
    const ta = a.lastMessage ? a.lastMessage.createdAt : "";
    const tb = b.lastMessage ? b.lastMessage.createdAt : "";
    return tb.localeCompare(ta);
  });
  res.json({ chats });
});

app.get("/api/chats/:id", requireAuth, (req, res) => {
  const chatId = Number(req.params.id);
  if (!isMember(chatId, req.session.userId)) return res.status(403).json({ error: "دسترسی نداری." });
  const preview = getChatPreview(chatId, req.session.userId);
  const members = db.prepare(`
    SELECT u.id, u.username, u.display_name, cm.role
    FROM chat_members cm JOIN users u ON u.id = cm.user_id
    WHERE cm.chat_id = ?
    ORDER BY CASE cm.role WHEN 'owner' THEN 0 WHEN 'admin' THEN 1 ELSE 2 END, u.display_name
  `).all(chatId).map(m => ({
    ...safeUser(m),
    role: m.role,
    online: onlineUsers.has(m.id)
  }));
  res.json({ chat: preview, members });
});

app.get("/api/chats/:id/messages", requireAuth, (req, res) => {
  const chatId = Number(req.params.id);
  if (!isMember(chatId, req.session.userId)) return res.status(403).json({ error: "دسترسی نداری." });

  const rows = db.prepare(`
    SELECT m.id, m.chat_id AS chatId, m.sender_id AS senderId, m.body, m.created_at AS createdAt,
           u.display_name AS senderName
    FROM messages m JOIN users u ON u.id = m.sender_id
    WHERE m.chat_id = ?
    ORDER BY m.id DESC LIMIT 150
  `).all(chatId).reverse();

  // Mark as read
  const maxId = rows.length ? rows[rows.length - 1].id : 0;
  if (maxId) {
    db.prepare("UPDATE chat_members SET last_read_id = MAX(last_read_id, ?) WHERE chat_id = ? AND user_id = ?")
      .run(maxId, chatId, req.session.userId);
  }

  res.json({ messages: rows });
});

// Start or get private chat
app.post("/api/chats/private", requireAuth, (req, res) => {
  const otherId = Number(req.body.userId);
  if (!Number.isSafeInteger(otherId) || otherId < 1 || otherId === req.session.userId) {
    return res.status(400).json({ error: "کاربر نامعتبر است." });
  }
  if (!userById.get(otherId)) return res.status(404).json({ error: "کاربر پیدا نشد." });

  // Find existing private chat
  const existing = db.prepare(`
    SELECT c.id FROM chats c
    JOIN chat_members m1 ON m1.chat_id = c.id AND m1.user_id = ?
    JOIN chat_members m2 ON m2.chat_id = c.id AND m2.user_id = ?
    WHERE c.type = 'private'
  `).get(req.session.userId, otherId);

  if (existing) {
    return res.json({ chat: getChatPreview(existing.id, req.session.userId) });
  }

  const result = db.prepare("INSERT INTO chats (type, created_by) VALUES ('private', ?)").run(req.session.userId);
  const chatId = Number(result.lastInsertRowid);
  db.prepare("INSERT INTO chat_members (chat_id, user_id, role) VALUES (?, ?, 'member')").run(chatId, req.session.userId);
  db.prepare("INSERT INTO chat_members (chat_id, user_id, role) VALUES (?, ?, 'member')").run(chatId, otherId);

  // Auto-add as contact both ways (optional, nice UX)
  db.prepare("INSERT OR IGNORE INTO contacts (user_id, contact_id) VALUES (?, ?)").run(req.session.userId, otherId);
  db.prepare("INSERT OR IGNORE INTO contacts (user_id, contact_id) VALUES (?, ?)").run(otherId, req.session.userId);

  res.status(201).json({ chat: getChatPreview(chatId, req.session.userId) });
});

// Create group
app.post("/api/chats/group", requireAuth, (req, res) => {
  const title = String(req.body.title || "").trim();
  const memberIds = Array.isArray(req.body.memberIds) ? req.body.memberIds.map(Number).filter(id => Number.isSafeInteger(id) && id > 0 && id !== req.session.userId) : [];

  if (title.length < 2 || title.length > 60) {
    return res.status(400).json({ error: "عنوان گروه باید بین ۲ تا ۶۰ کاراکتر باشد." });
  }
  if (memberIds.length > 50) {
    return res.status(400).json({ error: "حداکثر ۵۰ عضو می‌توانی اضافه کنی." });
  }

  const result = db.prepare("INSERT INTO chats (type, title, created_by) VALUES ('group', ?, ?)").run(title, req.session.userId);
  const chatId = Number(result.lastInsertRowid);
  db.prepare("INSERT INTO chat_members (chat_id, user_id, role) VALUES (?, ?, 'owner')").run(chatId, req.session.userId);

  const insertMember = db.prepare("INSERT OR IGNORE INTO chat_members (chat_id, user_id, role) VALUES (?, ?, 'member')");
  for (const mid of memberIds) {
    if (userById.get(mid)) insertMember.run(chatId, mid);
  }

  // Notify members via socket later
  res.status(201).json({ chat: getChatPreview(chatId, req.session.userId) });
});

// Create channel
app.post("/api/chats/channel", requireAuth, (req, res) => {
  const title = String(req.body.title || "").trim();
  const description = String(req.body.description || "").trim().slice(0, 300);

  if (title.length < 2 || title.length > 60) {
    return res.status(400).json({ error: "عنوان کانال باید بین ۲ تا ۶۰ کاراکتر باشد." });
  }

  const result = db.prepare("INSERT INTO chats (type, title, description, created_by) VALUES ('channel', ?, ?, ?)")
    .run(title, description, req.session.userId);
  const chatId = Number(result.lastInsertRowid);
  db.prepare("INSERT INTO chat_members (chat_id, user_id, role) VALUES (?, ?, 'owner')").run(chatId, req.session.userId);

  res.status(201).json({ chat: getChatPreview(chatId, req.session.userId) });
});

// Add members to group/channel
app.post("/api/chats/:id/members", requireAuth, (req, res) => {
  const chatId = Number(req.params.id);
  const memberIds = Array.isArray(req.body.memberIds) ? req.body.memberIds.map(Number) : [];
  const chat = db.prepare("SELECT type FROM chats WHERE id = ?").get(chatId);
  if (!chat) return res.status(404).json({ error: "گفتگو پیدا نشد." });

  const myRole = db.prepare("SELECT role FROM chat_members WHERE chat_id = ? AND user_id = ?").get(chatId, req.session.userId);
  if (!myRole || (myRole.role !== "owner" && myRole.role !== "admin")) {
    return res.status(403).json({ error: "فقط ادمین می‌تواند عضو اضافه کند." });
  }

  const insertMember = db.prepare("INSERT OR IGNORE INTO chat_members (chat_id, user_id, role) VALUES (?, ?, 'member')");
  let added = 0;
  for (const mid of memberIds) {
    if (Number.isSafeInteger(mid) && mid > 0 && userById.get(mid)) {
      const r = insertMember.run(chatId, mid);
      if (r.changes) added++;
    }
  }
  res.json({ ok: true, added });
});

// Join channel by id (simple public join)
app.post("/api/chats/:id/join", requireAuth, (req, res) => {
  const chatId = Number(req.params.id);
  const chat = db.prepare("SELECT type FROM chats WHERE id = ?").get(chatId);
  if (!chat || chat.type !== "channel") return res.status(400).json({ error: "فقط کانال‌ها قابل عضویت عمومی هستند." });
  db.prepare("INSERT OR IGNORE INTO chat_members (chat_id, user_id, role) VALUES (?, ?, 'member')").run(chatId, req.session.userId);
  res.json({ chat: getChatPreview(chatId, req.session.userId) });
});

// ---------- Socket.IO ----------
io.use((socket, next) => {
  sessionMiddleware(socket.request, {}, next);
});
io.use((socket, next) => {
  if (!socket.request.session || !socket.request.session.userId) {
    return next(new Error("unauthorized"));
  }
  next();
});

io.on("connection", socket => {
  const userId = socket.request.session.userId;
  socket.join(`user:${userId}`);

  // Join all chat rooms the user belongs to
  const myChats = db.prepare("SELECT chat_id FROM chat_members WHERE user_id = ?").all(userId);
  myChats.forEach(c => socket.join(`chat:${c.chat_id}`));

  if (!onlineUsers.has(userId)) onlineUsers.set(userId, new Set());
  onlineUsers.get(userId).add(socket.id);
  io.emit("presence", { userId, online: true });

  socket.on("send_message", payload => {
    const chatId = Number(payload && payload.chatId);
    const body = String(payload && payload.body || "").trim();

    if (!Number.isSafeInteger(chatId) || chatId < 1 || body.length < 1 || body.length > 4000) {
      socket.emit("chat_error", { error: "پیام یا گفتگو نامعتبر است." });
      return;
    }
    if (!isMember(chatId, userId)) {
      socket.emit("chat_error", { error: "عضو این گفتگو نیستی." });
      return;
    }
    if (!canPost(chatId, userId)) {
      socket.emit("chat_error", { error: "در کانال فقط ادمین‌ها می‌توانند پیام بفرستند." });
      return;
    }

    const result = db.prepare(
      "INSERT INTO messages (chat_id, sender_id, body) VALUES (?, ?, ?)"
    ).run(chatId, userId, body);

    const message = db.prepare(`
      SELECT m.id, m.chat_id AS chatId, m.sender_id AS senderId, m.body, m.created_at AS createdAt,
             u.display_name AS senderName
      FROM messages m JOIN users u ON u.id = m.sender_id
      WHERE m.id = ?
    `).get(Number(result.lastInsertRowid));

    // Update last_read for sender
    db.prepare("UPDATE chat_members SET last_read_id = ? WHERE chat_id = ? AND user_id = ?")
      .run(message.id, chatId, userId);

    io.to(`chat:${chatId}`).emit("new_message", message);
  });

  socket.on("join_chat", chatId => {
    chatId = Number(chatId);
    if (isMember(chatId, userId)) {
      socket.join(`chat:${chatId}`);
    }
  });

  socket.on("typing", payload => {
    const chatId = Number(payload && payload.chatId);
    if (isMember(chatId, userId)) {
      socket.to(`chat:${chatId}`).emit("typing", { chatId, userId, displayName: safeUser(userById.get(userId))?.displayName });
    }
  });

  socket.on("disconnect", () => {
    const sockets = onlineUsers.get(userId);
    if (sockets) {
      sockets.delete(socket.id);
      if (sockets.size === 0) {
        onlineUsers.delete(userId);
        db.prepare("UPDATE users SET last_seen = datetime('now') WHERE id = ?").run(userId);
        io.emit("presence", { userId, online: false });
      }
    }
  });
});

app.get("*", (req, res) => res.sendFile(path.join(__dirname, "public", "index.html")));

server.listen(PORT, () => {
  console.log(`Nova Messenger is running at http://localhost:${PORT}`);
});
