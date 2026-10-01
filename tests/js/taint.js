const express = require("express");
const fs = require("fs");
const path = require("path");
const vm = require("vm");
const axios = require("axios");
const ejs = require("ejs");
const _ = require("lodash");
const serialize = require("node-serialize");
const { exec, execFile } = require("child_process");

const app = express();

app.get("/user", (req, res) => {
  const id = req.query.id;
  const sql = "SELECT * FROM users WHERE id = '" + id + "'";
  // ruleid: js-taint-sqli
  db.query(sql, (err, rows) => res.json(rows));
  // ok: js-taint-sqli
  db.query("SELECT * FROM users WHERE id = ?", [id], (err, rows) => res.json(rows));
  const n = parseInt(req.query.n);
  // ok: js-taint-sqli
  db.query(`SELECT * FROM users LIMIT ${n}`);
});

app.post("/login", async (req, res) => {
  const { username, password } = req.body;
  // ruleid: js-taint-nosqli
  const user = await User.findOne({ username: username, password: password });
  // ok: js-taint-nosqli
  const user2 = await User.findOne({ username: String(username) });
  res.json(user || user2);
});

app.get("/ping", (req, res) => {
  const host = req.query.host;
  // ruleid: js-taint-command-injection
  exec(`ping -c 1 ${host}`, (e, out) => res.send(out));
  // ok: js-taint-command-injection
  execFile("ping", ["-c", "1", host], (e, out) => res.send(out));
});

app.post("/calc", (req, res) => {
  const expr = req.body.expr;
  // ruleid: js-taint-code-injection
  const result = vm.runInNewContext(expr, {});
  res.json({ result });
});

app.get("/file", (req, res) => {
  const name = req.query.name;
  const full = path.join(__dirname, "uploads", name);
  // ruleid: js-taint-path-traversal
  const data = fs.readFileSync(full);
  // ruleid: js-taint-path-traversal
  res.sendFile(full);
  // ok: js-taint-path-traversal
  res.sendFile(path.join(__dirname, "uploads", path.basename(name)));
});

app.get("/proxy", async (req, res) => {
  const target = req.query.url;
  // ruleid: js-taint-ssrf
  const r = await axios.get(target);
  // ruleid: js-taint-xss-response
  res.send(r.data);
});

app.get("/preview", (req, res) => {
  const tpl = "<h1>" + req.query.title + "</h1>";
  // ruleid: js-taint-ssti
  const html = ejs.render(tpl);
  // ok: js-taint-ssti
  const html2 = ejs.render("<h1><%= title %></h1>", { title: req.query.title });
  // ruleid: js-taint-xss-response
  res.type("html").send(html + html2);
});

app.post("/settings", (req, res) => {
  const settings = {};
  // ruleid: js-taint-prototype-pollution
  _.merge(settings, req.body);
  const { section, key, value } = req.body;
  // ruleid: js-taint-prototype-pollution
  settings[section][key] = value;
  res.json(settings);
});

app.post("/restore", (req, res) => {
  const blob = Buffer.from(req.cookies.profile, "base64").toString();
  // ruleid: js-taint-deserialization
  const obj = serialize.unserialize(blob);
  res.json(obj);
});

app.get("/go", (req, res) => {
  // ruleid: js-taint-open-redirect
  res.redirect(req.query.next);
});

app.get("/hello", (req, res) => {
  const name = req.query.name;
  // ruleid: js-taint-xss-response
  res.send("<h1>Hello " + name + "</h1>");
  // ok: js-taint-xss-response
  res.send({ hello: name });
});

app.get("/search", (req, res) => {
  // ruleid: js-taint-regex-injection
  const re = new RegExp(req.query.q);
  // ok: js-taint-regex-injection
  const re2 = new RegExp(_.escapeRegExp(req.query.q));
  res.json(notes.filter((n) => re.test(n) || re2.test(n)));
});
