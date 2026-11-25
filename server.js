const express = require("express");
const fs = require("fs");
const path = require("path");
const crypto = require("crypto");

const app = express();
const PORT = process.env.PORT || 3000;

const OWNER_PASSWORD = process.env.OWNER_PASSWORD || "SOS@2026";
const DB_FILE = path.join(__dirname, "licenses.json");
const INDEX_FILE = path.join(__dirname, "index.html");

const activeSessions = new Map();

app.use(express.json());
app.use(express.urlencoded({ extended: true }));

// CORS allow taake Chrome extensions kisi bhi origin/URL se request bhej sakein
app.use((req, res, next) => {
  res.header("Access-Control-Allow-Origin", "*");
  res.header("Access-Control-Allow-Methods", "GET, POST, PUT, DELETE, OPTIONS");
  res.header("Access-Control-Allow-Headers", "Content-Type, Authorization, x-admin-token");
  if (req.method === "OPTIONS") {
    return res.sendStatus(200);
  }
  next();
});

function loadLicenses() {
  try {
    if (!fs.existsSync(DB_FILE)) {
      fs.writeFileSync(DB_FILE, JSON.stringify({}, null, 2), "utf8");
      return {};
    }
    const raw = fs.readFileSync(DB_FILE, "utf8").trim();
    if (!raw) return {};
    return JSON.parse(raw);
  } catch (err) {
    console.error("Error reading licenses.json:", err);
    return {};
  }
}

function saveLicenses(data) {
  try {
    fs.writeFileSync(DB_FILE, JSON.stringify(data, null, 2), "utf8");
    return true;
  } catch (err) {
    console.error("Error writing licenses.json:", err);
    return false;
  }
}

function getToken(req) {
  const auth = req.headers["authorization"] || "";
  if (auth.startsWith("Bearer ")) {
    return auth.slice(7).trim();
  }
  return (req.headers["x-admin-token"] || req.body?.token || req.query?.token || "").trim();
}

function requireAdmin(req, res, next) {
  const token = getToken(req);
  if (!token || !activeSessions.has(token)) {
    return res.status(401).json({ ok: false, error: "Unauthorized. Please login with SOS@2026." });
  }
  next();
}

const EXT_MAP = {
  FAL: { name: "Facebook Auto Listing (FAL)", prefix: "" },
  LOC: { name: "S ❤️ S Auto Location Pro", prefix: "LOC-PC-" },
  PUB: { name: "S ❤️ S FB Auto-Publish", prefix: "PUB-PC-" }
};

function getLicenseStatus(rec, now = Date.now()) {
  if (!rec) return "Invalid";
  if (rec.revoked) return "Blocked";
  if (now > Number(rec.expiresAt || 0)) return "Expired";
  return "Active";
}

// Health check
app.get("/api/health", (req, res) => {
  res.json({ ok: true, status: "online", time: Date.now() });
});

// Owner Login
app.post("/api/login", (req, res) => {
  const password = String(req.body?.password || "").trim();
  if (password !== OWNER_PASSWORD) {
    return res.status(401).json({ ok: false, error: "Invalid password" });
  }
  const token = crypto.randomBytes(24).toString("hex");
  activeSessions.set(token, Date.now() + 24 * 60 * 60 * 1000);
  return res.json({ ok: true, token });
});

// Generate Activation Key (Admin)
app.post("/api/generate", requireAdmin, (req, res) => {
  const extType = String(req.body?.extType || req.body?.extension || "FAL").trim().toUpperCase();
  const cfg = EXT_MAP[extType] || { name: req.body?.extName || extType, prefix: "" };
  const hwid = String(req.body?.hwid || "").trim();
  const clientName = String(req.body?.clientName || req.body?.name || "Client").trim() || "Client";
  const days = Math.min(3650, Math.max(1, parseInt(req.body?.days || req.body?.validDays || 7, 10) || 7));

  if (!hwid) {
    return res.status(400).json({ ok: false, error: "Client HWID is required" });
  }

  const code = Math.floor(10000 + Math.random() * 90000);
  const cleanHwid = hwid.replace(/\s+/g, "").toUpperCase();
  const baseHwid = cfg.prefix && !cleanHwid.startsWith(cfg.prefix) ? cfg.prefix + cleanHwid : cleanHwid;
  const licenseKey = `${baseHwid}-${code}`;

  const now = Date.now();
  const expiresAt = now + days * 24 * 60 * 60 * 1000;

  const db = loadLicenses();
  db[licenseKey] = {
    key: licenseKey,
    extType,
    extName: cfg.name,
    clientName,
    hwid: cleanHwid,
    createdAt: now,
    expiresAt,
    revoked: false,
    activatedAt: null,
    lastCheckedAt: null
  };

  if (!saveLicenses(db)) {
    return res.status(500).json({ ok: false, error: "Failed to save license record" });
  }

  return res.json({
    ok: true,
    key: licenseKey,
    record: db[licenseKey]
  });
});

// List all licenses (Admin)
app.get("/api/licenses", requireAdmin, (req, res) => {
  const db = loadLicenses();
  const now = Date.now();
  const list = Object.values(db)
    .map((item) => ({
      ...item,
      status: getLicenseStatus(item, now)
    }))
    .sort((a, b) => (b.createdAt || 0) - (a.createdAt || 0));

  return res.json({ ok: true, licenses: list });
});

// Block / Unblock license (Admin)
app.post("/api/toggle-block", requireAdmin, (req, res) => {
  const key = String(req.body?.key || "").trim();
  const db = loadLicenses();
  if (!db[key]) {
    return res.status(404).json({ ok: false, error: "License key not found" });
  }
  db[key].revoked = !db[key].revoked;
  saveLicenses(db);
  return res.json({
    ok: true,
    key,
    revoked: db[key].revoked,
    status: getLicenseStatus(db[key])
  });
});

// Delete license (Admin)
app.delete("/api/licenses/:key", requireAdmin, (req, res) => {
  const key = decodeURIComponent(req.params.key || "").trim();
  const db = loadLicenses();
  if (!db[key]) {
    return res.status(404).json({ ok: false, error: "License key not found" });
  }
  delete db[key];
  saveLicenses(db);
  return res.json({ ok: true, deleted: key });
});

// Extension Activation Endpoint
app.post("/api/activate", (req, res) => {
  const key = String(req.body?.key || req.body?.licenseKey || "").trim().toUpperCase();
  const hwid = String(req.body?.hwid || "").trim().toUpperCase();
  const extType = String(req.body?.extType || req.body?.extension || "").trim().toUpperCase();

  if (!key) {
    return res.status(400).json({ ok: false, valid: false, error: "License key is required" });
  }

  const db = loadLicenses();
  const rec = db[key];
  if (!rec) {
    return res.status(404).json({ ok: false, valid: false, error: "Invalid license key" });
  }

  if (rec.revoked) {
    return res.status(403).json({ ok: false, valid: false, error: "License is blocked" });
  }

  const now = Date.now();
  if (now > Number(rec.expiresAt || 0)) {
    return res.status(403).json({ ok: false, valid: false, error: "License has expired" });
  }

  if (hwid && rec.hwid && hwid !== rec.hwid) {
    return res.status(403).json({ ok: false, valid: false, error: "HWID mismatch" });
  }

  if (extType && rec.extType && extType !== rec.extType) {
    return res.status(403).json({ ok: false, valid: false, error: "Key is for a different extension" });
  }

  if (!rec.activatedAt) {
    rec.activatedAt = now;
  }
  rec.lastCheckedAt = now;
  saveLicenses(db);

  return res.json({
    ok: true,
    valid: true,
    status: "Active",
    key: rec.key,
    extType: rec.extType,
    expiresAt: rec.expiresAt
  });
});

// Extension Verify Endpoint
app.post("/api/verify", (req, res) => {
  const key = String(req.body?.key || req.body?.licenseKey || "").trim().toUpperCase();
  const hwid = String(req.body?.hwid || "").trim().toUpperCase();

  if (!key) {
    return res.status(400).json({ ok: false, valid: false, error: "License key missing" });
  }

  const db = loadLicenses();
  const rec = db[key];
  if (!rec) {
    return res.status(404).json({ ok: false, valid: false, error: "Invalid license key" });
  }

  const status = getLicenseStatus(rec);
  if (status !== "Active") {
    return res.status(403).json({ ok: false, valid: false, status, error: `License is ${status}` });
  }

  if (hwid && rec.hwid && hwid !== rec.hwid) {
    return res.status(403).json({ ok: false, valid: false, error: "HWID mismatch" });
  }

  rec.lastCheckedAt = Date.now();
  saveLicenses(db);

  return res.json({
    ok: true,
    valid: true,
    status: "Active",
    key: rec.key,
    extType: rec.extType,
    expiresAt: rec.expiresAt
  });
});

// Dashboard HTML serve karein agar index.html maujood ho
app.get("/", (req, res) => {
  if (fs.existsSync(INDEX_FILE)) {
    return res.sendFile(INDEX_FILE);
  }
  return res.send("S ❤️ S License Server is running.");
});

app.listen(PORT, () => {
  console.log(`S <3 S Server running on port ${PORT}`);
});