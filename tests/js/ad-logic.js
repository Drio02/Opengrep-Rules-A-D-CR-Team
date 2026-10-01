const express = require("express");
const session = require("express-session");
const cookieParser = require("cookie-parser");
const jwt = require("jsonwebtoken");
const bcrypt = require("bcrypt");
const crypto = require("crypto");
const cors = require("cors");

const app = express();
// ruleid: js-hardcoded-session-secret
app.use(session({ secret: "keyboard cat", resave: false }));
// ruleid: js-hardcoded-session-secret
app.use(cookieParser("s3cr3t"));
// ok: js-hardcoded-session-secret
app.use(session({ secret: process.env.SESSION_SECRET, resave: false }));
// ruleid: js-ip-based-auth-spoofable
app.set("trust proxy", true);
// ruleid: js-cors-reflect-origin-with-credentials
app.use(cors({ origin: true, credentials: true }));

function issue(user) {
  // ruleid: js-jwt-hardcoded-secret
  return jwt.sign({ id: user.id }, "jwt_secret_123");
}

function check(token, key) {
  // ruleid: js-jwt-verify-without-algorithms
  const a = jwt.verify(token, key);
  // ok: js-jwt-verify-without-algorithms
  const b = jwt.verify(token, key, { algorithms: ["HS256"] });
  return a || b;
}

function resetCode() {
  // ruleid: js-weak-random-token
  return Math.floor(Math.random() * 1e6).toString();
}

function apiAuth(req) {
  const apiKey = req.headers["x-api-key"];
  // ruleid: js-timing-unsafe-secret-compare
  if (apiKey == process.env.API_KEY) return true;
  // ok: js-timing-unsafe-secret-compare
  return crypto.timingSafeEqual(Buffer.from(String(apiKey)), Buffer.from(process.env.API_KEY));
}

app.post("/login", async (req, res) => {
  const user = await User.findOne({ username: String(req.body.username) });
  // ruleid: js-password-compare-not-awaited
  if (bcrypt.compare(req.body.password, user.hash)) {
    req.session.user = user.id;
  }
  // ok: js-password-compare-not-awaited
  if (await bcrypt.compare(req.body.password, user.hash)) {
    req.session.user = user.id;
  }
  res.end();
});

app.get("/page", (req, res) => {
  // ruleid: js-res-render-user-options
  res.render("page", req.query);
  // ok: js-res-render-user-options
  res.render("page", { name: req.query.name });
});

app.post("/register", async (req, res) => {
  // ruleid: js-mass-assignment
  const u = await User.create(req.body);
  // ok: js-mass-assignment
  const v = await User.create({ name: req.body.name });
  res.json([u, v]);
});

// ruleid: js-sensitive-route-without-middleware
app.get("/admin/flags", async (req, res) => {
  res.json(await Flag.find({}));
});

// ok: js-sensitive-route-without-middleware
app.get("/admin/users", requireAdmin, async (req, res) => {
  res.json(await User.find({}));
});

// ok: js-sensitive-route-without-middleware
app.get("/export", async (req, res) => {
  if (!req.session.isAdmin) return res.sendStatus(403);
  res.json(await Note.find({}));
});

// ruleid: js-sensitive-route-without-middleware
app.get("/internal", (req, res) => {
  // ruleid: js-ip-based-auth-spoofable
  const ip = req.headers["x-forwarded-for"];
  if (ip === "127.0.0.1") res.send(process.env.FLAG);
});

function tmp(n) {
  // ruleid: js-unsafe-buffer-allocation
  const b = Buffer.allocUnsafe(n);
  // ok: js-unsafe-buffer-allocation
  const c = Buffer.alloc(n);
  return [b, c];
}

function enc(key, data) {
  // ruleid: js-weak-cipher
  const c = crypto.createCipheriv("aes-128-ecb", key, null);
  // ok: js-weak-cipher
  const d = crypto.createCipheriv("aes-256-gcm", key, crypto.randomBytes(12));
  return [c, d];
}

app.get("/check", (req, res) => {
  // ruleid: js-type-confusion-query-array
  if (req.query.name.includes("admin")) return res.sendStatus(403);
  res.end();
});
