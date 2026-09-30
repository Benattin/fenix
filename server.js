"use strict";
const http = require("http");
const https = require("https");
const tls = require("tls");
const fs = require("fs");
const path = require("path");
const { URL } = require("url");

const PORT = Number(process.env.FENIX_PORT) || 4250;
const HOST = "127.0.0.1";
const ALLOW_PROXY = new Set(["calendar.google.com", "news.google.com"]);
const ALLOW_IMAP = new Set(["imap.gmail.com"]);
const UA = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/122.0.0.0 Safari/537.36";

function cors(res) {
  res.setHeader("Access-Control-Allow-Origin", "*");
  res.setHeader("Access-Control-Allow-Methods", "GET, POST, OPTIONS");
  res.setHeader("Access-Control-Allow-Headers", "Content-Type");
}

function send(res, code, body, type) {
  if (res.headersSent || res.writableEnded) return;
  cors(res);
  res.writeHead(code, { "Content-Type": type || "text/plain; charset=utf-8" });
  res.end(body);
}
function writeJson(file, obj) {
  fs.mkdirSync(path.dirname(file), { recursive: true });
  const tmp = file + ".tmp";
  fs.writeFileSync(tmp, JSON.stringify(obj));
  try {
    fs.renameSync(tmp, file);
  } catch (e) {
    try { fs.writeFileSync(file, JSON.stringify(obj)); } catch (e2) {}
    try { fs.unlinkSync(tmp); } catch (e3) {}
  }
}
function proxyHostOk(u) {
  const h = String(u.hostname || "").toLowerCase();
  const pathq = u.pathname + u.search;
  return ALLOW_PROXY.has(h) ||
    (h === "www.google.com" && /rss|news|calendar|ical/i.test(pathq)) ||
    (/googleusercontent\.com$/i.test(h) && /\.ics|calendar|ical/i.test(pathq)) ||
    (/^calendar\.google\.com$/i.test(h));
}

const VAULT = path.join(__dirname, "data", "vault");
function ensureVault() {
  fs.mkdirSync(VAULT, { recursive: true });
}
function vaultAbs(rel) {
  const clean = String(rel || "").replace(/\\/g, "/").replace(/^\/+/, "");
  if (clean.split("/").some(p => !p || p === "." || p === "..")) {
    const e = new Error("caminho inválido");
    e.code = 400;
    throw e;
  }
  const abs = path.resolve(VAULT, clean);
  if (abs !== VAULT && !abs.startsWith(VAULT + path.sep)) {
    const e = new Error("fora do cofre");
    e.code = 403;
    throw e;
  }
  return abs;
}
function listVault(rel) {
  ensureVault();
  const dir = rel ? vaultAbs(rel) : VAULT;
  if (!fs.existsSync(dir)) return { dir: rel || "", items: [] };
  const items = fs.readdirSync(dir, { withFileTypes: true }).map(d => {
    const st = fs.statSync(path.join(dir, d.name));
    return { name: d.name, folder: d.isDirectory(), size: st.size, mtime: st.mtimeMs };
  }).sort((a, b) => Number(b.folder) - Number(a.folder) || a.name.localeCompare(b.name, "pt"));
  return { dir: rel || "", items: items };
}

function isMostlyText(buf) {
  if (!buf.length) return false;
  let bad = 0;
  const n = Math.min(buf.length, 800);
  for (let i = 0; i < n; i++) {
    const c = buf[i];
    if (c === 0) return false;
    if (c < 9 || (c > 13 && c < 32)) bad++;
  }
  return bad / n < 0.08;
}

function extractPdfText(buf) {
  const s = buf.toString("latin1");
  const bits = [];
  const re = /\(((?:\\.|[^\\)]){3,})\)\s*Tj/g;
  let m;
  while ((m = re.exec(s)) && bits.length < 80) {
    bits.push(m[1].replace(/\\([\\()])/g, "$1").replace(/\\n/g, " "));
  }
  return bits.join(" ").replace(/\s+/g, " ").trim().slice(0, 8000);
}

const MIME = {
  ".png": "image/png", ".jpg": "image/jpeg", ".jpeg": "image/jpeg",
  ".gif": "image/gif", ".webp": "image/webp", ".svg": "image/svg+xml", ".bmp": "image/bmp"
};

function sniffImage(buf) {
  if (!buf || buf.length < 12) return false;
  if (buf[0] === 0x89 && buf[1] === 0x50 && buf[2] === 0x4e) return true;
  if (buf[0] === 0xff && buf[1] === 0xd8) return true;
  if (buf[0] === 0x47 && buf[1] === 0x49 && buf[2] === 0x46) return true;
  if (buf.toString("ascii", 0, 4) === "RIFF" && buf.toString("ascii", 8, 12) === "WEBP") return true;
  return false;
}

function peekVault(rel) {
  const abs = vaultAbs(rel);
  if (!fs.existsSync(abs) || fs.statSync(abs).isDirectory()) {
    const e = new Error("arquivo não encontrado");
    e.code = 404;
    throw e;
  }
  const st = fs.statSync(abs);
  const name = path.basename(abs);
  const ext = path.extname(name).toLowerCase();
  const buf = fs.readFileSync(abs);
  const cap = buf.slice(0, 80 * 1024);
  const textExt = /\.(txt|md|json|js|mjs|cjs|ts|tsx|jsx|py|html|htm|css|csv|log|xml|yml|yaml|ini|sql|sh|bat|ps1|c|cpp|h|java|go|rs|php|rb|vue)$/i;
  let kind = "bin";
  let text = "";
  if (textExt.test(ext) || isMostlyText(cap)) {
    kind = "text";
    text = cap.toString("utf8").replace(/\u0000/g, "");
  } else if (MIME[ext] || sniffImage(buf)) {
    kind = "image";
  } else if (ext === ".pdf") {
    kind = "pdf";
    text = extractPdfText(cap);
  }
  const out = {
    name: name,
    ext: ext,
    mime: MIME[ext] || (kind === "image" ? "image/jpeg" : "application/octet-stream"),
    size: st.size,
    kind: kind,
    text: String(text || "").slice(0, 24000),
    truncated: buf.length > cap.length
  };
  if (kind === "image" && buf.length <= 2.5 * 1024 * 1024) out.b64 = buf.toString("base64");
  return out;
}

function findVault(q, kind) {
  const needle = String(q || "").toLowerCase().replace(/[\\/]/g, "").trim();
  const hits = [];
  function walk(prefix) {
    if (hits.length >= 40) return;
    listVault(prefix).items.forEach(function (it) {
      const rel = prefix ? prefix + "/" + it.name : it.name;
      if (it.folder) { walk(rel); return; }
      const ext = path.extname(it.name).toLowerCase();
      if (kind === "image" && !MIME[ext]) return;
      if (!needle || it.name.toLowerCase().indexOf(needle) >= 0) hits.push({ path: rel, mtime: it.mtime });
    });
  }
  walk("");
  hits.sort((a, b) => (b.mtime || 0) - (a.mtime || 0));
  return { q: needle, path: (hits[0] && hits[0].path) || "", hits: hits.map(h => h.path) };
}

function fetchUrl(target, hops) {
  if (hops < 0) return Promise.reject(new Error("muitos redirects"));
  const u = new URL(target);
    if (!proxyHostOk(u)) {
      const err = new Error("domínio não permitido");
      err.code = 403;
      return Promise.reject(err);
    }
  return new Promise((resolve, reject) => {
    const lib = u.protocol === "http:" ? http : https;
    const req = lib.request({
      hostname: u.hostname,
      path: u.pathname + u.search,
      method: "GET",
      headers: { "User-Agent": UA, Accept: "text/calendar, application/rss+xml, application/xml, text/xml, */*" }
    }, rec => {
      const chunks = [];
      rec.on("data", c => {
        chunks.push(c);
        const n = chunks.reduce((s, x) => s + x.length, 0);
        if (n > 8 * 1024 * 1024) {
          rec.destroy();
          reject(new Error("resposta grande demais"));
        }
      });
      rec.on("end", () => {
        const buf = Buffer.concat(chunks);
        if (rec.statusCode >= 300 && rec.statusCode < 400 && rec.headers.location) {
          let next = rec.headers.location;
          try { next = new URL(next, u).href; } catch (e) {}
          fetchUrl(next, hops - 1).then(resolve, reject);
          return;
        }
        if (rec.statusCode >= 400) {
          const err = new Error("http " + rec.statusCode);
          err.code = rec.statusCode;
          reject(err);
          return;
        }
        const cs = /charset=([\w-]+)/i.exec(String(rec.headers["content-type"] || ""));
        let text = buf.toString("utf8");
        if (cs && /iso-8859-1|latin1|windows-1252/i.test(cs[1])) text = buf.toString("latin1");
        resolve(text);
      });
    });
    req.on("error", reject);
    req.setTimeout(20000, () => { req.destroy(new Error("timeout")); });
    req.end();
  });
}

function qImap(s) {
  return '"' + String(s).replace(/\\/g, "\\\\").replace(/"/g, '\\"') + '"';
}

function decodeMimeWord(s) {
  return String(s || "").replace(/=\?([^?]+)\?([BQbq])\?([^?]+)\?=/g, (_, cs, enc, data) => {
    try {
      if (enc.toUpperCase() === "B") return Buffer.from(data, "base64").toString("utf8");
      const q = data.replace(/_/g, " ").replace(/=([0-9A-Fa-f]{2})/g, (m, h) => String.fromCharCode(parseInt(h, 16)));
      return q;
    } catch (e) { return data; }
  });
}

function decodeQP(s) {
  return String(s || "").replace(/=\r?\n/g, "").replace(/=([0-9A-Fa-f]{2})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
}

function stripHtml(s) {
  return String(s || "").replace(/<script[\s\S]*?<\/script>/gi, " ").replace(/<style[\s\S]*?<\/style>/gi, " ").replace(/<[^>]+>/g, " ").replace(/&nbsp;/g, " ").replace(/&amp;/g, "&").replace(/&lt;/g, "<").replace(/&gt;/g, ">").replace(/\s+/g, " ").trim();
}

function makeReader(sock) {
  let buf = Buffer.alloc(0);
  let wake = null;
  sock.on("data", c => {
    buf = Buffer.concat([buf, c]);
    if (wake) { const w = wake; wake = null; w(); }
  });
  function wait() {
    return new Promise(r => {
      if (buf.length) return r();
      wake = r;
    });
  }
  async function readLine() {
    for (;;) {
      const i = buf.indexOf("\r\n");
      if (i >= 0) {
        const line = buf.slice(0, i).toString("utf8");
        buf = buf.slice(i + 2);
        return line;
      }
      await wait();
    }
  }
  async function readExact(n) {
    while (buf.length < n) await wait();
    const out = buf.slice(0, n);
    buf = buf.slice(n);
    return out;
  }
  async function readImapLine() {
    let line = await readLine();
    for (;;) {
      const lit = /\{(\d+)\}$/.exec(line);
      if (!lit) return line;
      const payload = await readExact(Number(lit[1]));
      line = line.slice(0, -lit[0].length) + payload.toString("utf8");
      line += await readLine();
    }
  }
  let t = 0;
  async function cmd(command) {
    const tag = "A" + (++t);
    sock.write(tag + " " + command + "\r\n");
    const lines = [];
    let exists = 0;
    for (;;) {
      const line = await readImapLine();
      const ex = /^\* (\d+) EXISTS/i.exec(line);
      if (ex) exists = Number(ex[1]);
      if (line.indexOf(tag + " ") === 0) {
        return { ok: / OK /i.test(line), line: line, lines: lines, exists: exists, raw: lines.join("\n") };
      }
      lines.push(line);
    }
  }
  async function greeting() {
    for (;;) {
      const line = await readImapLine();
      if (/^\* OK/i.test(line) || /^\* PREAUTH/i.test(line)) return;
      if (/^\* BYE/i.test(line)) throw new Error("servidor encerrou");
    }
  }
  return { cmd: cmd, greeting: greeting };
}

function parseFetchRaw(raw) {
  const chunks = raw.split(/\n(?=\* \d+ FETCH )/i);
  const out = [];
  chunks.forEach(ch => {
    if (!/\* \d+ FETCH /i.test(ch)) return;
    const hdr = {};
    const hm = /BODY\[HEADER\.FIELDS[^\]]*\](?:<\d+\.\d+>)?\s*/i.exec(ch);
    let headerText = ch;
    const from = /^From:\s*(.+)$/im.exec(ch);
    const subj = /^Subject:\s*(.+)$/im.exec(ch);
    const date = /^Date:\s*(.+)$/im.exec(ch);
    const mid = /^Message-ID:\s*(.+)$/im.exec(ch);
    hdr.from = decodeMimeWord(from ? from[1].trim() : "");
    hdr.subject = decodeMimeWord(subj ? subj[1].trim() : "(sem assunto)");
    hdr.date = date ? date[1].trim() : "";
    hdr.id = mid ? mid[1].trim().replace(/^<|>$/g, "") : "";
    const flags = /FLAGS \(([^\)]*)\)/i.exec(ch);
    const seen = flags ? /\\Seen/i.test(flags[1]) : false;
    let body = "";
    const bm = /BODY\[TEXT\](?:<[^>]+>)?\s*([\s\S]*)/i.exec(ch);
    if (bm) body = bm[1];
    else {
      const after = ch.split(/\r?\n\r?\n/);
      if (after[1]) body = after.slice(1).join("\n");
    }
    body = body.replace(/\)\s*$/, "");
    if (/Content-Transfer-Encoding:\s*base64/i.test(headerText) || /^[A-Za-z0-9+/=\s]{80,}$/.test(body.slice(0, 200))) {
      try { body = Buffer.from(body.replace(/\s+/g, ""), "base64").toString("utf8"); } catch (e) {}
    } else {
      body = decodeQP(body);
    }
    if (/<html|<[a-z]+[\s>]/i.test(body)) body = stripHtml(body);
    body = body.replace(/\s+/g, " ").trim().slice(0, 500);
    if (!hdr.id) hdr.id = (hdr.from + "|" + hdr.subject + "|" + hdr.date).slice(0, 180);
    out.push({
      id: hdr.id,
      remetente: hdr.from,
      assunto: hdr.subject,
      data: hdr.date,
      trecho: body,
      lido: seen
    });
  });
  return out;
}

function fetchEmails(host, usuario, senhaApp, quantidade) {
  return new Promise((resolve, reject) => {
    if (!ALLOW_IMAP.has(host)) {
      const e = new Error("host IMAP não permitido");
      e.code = 403;
      reject(e);
      return;
    }
    const sock = tls.connect({ host: host, port: 993, servername: host }, async () => {
      let r;
      try {
        r = makeReader(sock);
        await r.greeting();
        const login = await r.cmd("LOGIN " + qImap(usuario) + " " + qImap(String(senhaApp || "").replace(/\s+/g, "")));
        if (!login.ok) {
          const e = new Error("login");
          e.code = 401;
          reject(e);
          return;
        }
        const ex = await r.cmd("EXAMINE INBOX");
        const exists = ex.exists;
        if (!exists) {
          resolve([]);
          return;
        }
        const n = Math.max(1, Math.min(Number(quantidade) || 20, 50));
        const from = Math.max(1, exists - n + 1);
        const fe = await r.cmd("FETCH " + from + ":" + exists + " (FLAGS BODY.PEEK[HEADER.FIELDS (FROM SUBJECT DATE MESSAGE-ID)] BODY.PEEK[TEXT]<0.700>)");
        resolve(parseFetchRaw(fe.raw || ""));
      } catch (err) {
        reject(err);
      } finally {
        try { if (r) await r.cmd("LOGOUT"); } catch (e) {}
        try { sock.end(); } catch (e) {}
      }
    });
    sock.on("error", reject);
    sock.setTimeout(40000, () => {
      sock.destroy();
      reject(new Error("timeout IMAP"));
    });
  });
}

const STALE_FACTOR = 2.5; // atrasado se age_min > every_min * 2.5
const AGENT_DIR = path.join(__dirname, "data", "agents");
const CATALOG = [
  { id: "agenda", nome: "AGENDA", icon: "📅", faz: "Junta as agendas do Google numa timeline.", every_min: 10, arquivo: "data/agents/agenda.json", run: { url: "/api/agents/run", method: "POST", body: { id: "agenda" } } },
  { id: "emails", nome: "E-MAILS", icon: "📬", faz: "Lê a caixa e separa o que pede ação.", every_min: 15, arquivo: "data/agents/emails.json", run: { url: "/api/agents/run", method: "POST", body: { id: "emails" } } },
  { id: "noticias", nome: "NOTÍCIAS", icon: "📡", faz: "Busca manchetes de tecnologia e economia.", every_min: 30, arquivo: "data/agents/noticias.json", run: { url: "/api/agents/run", method: "POST", body: { id: "noticias" } } },
  { id: "digest", nome: "DIGEST", icon: "☀", faz: "Monta o briefing da manhã uma vez por dia.", every_min: 1440, arquivo: "data/agents/digest.json", run: null }
];

function readAgentFile(id) {
  const p = path.join(AGENT_DIR, id + ".json");
  try {
    return { ok: true, data: JSON.parse(fs.readFileSync(p, "utf8")) };
  } catch (e) {
    if (e.code === "ENOENT") return { ok: true, data: null };
    return { ok: false, error: String(e.message || e) };
  }
}

function writeAgent(id, patch) {
  fs.mkdirSync(AGENT_DIR, { recursive: true });
  const p = path.join(AGENT_DIR, id + ".json");
  let prev = {};
  try {
    prev = JSON.parse(fs.readFileSync(p, "utf8"));
  } catch (e) {
    if (e.code !== "ENOENT") throw e;
  }
  const next = Object.assign({}, prev, patch, { id: id });
  writeJson(p, next);
  return next;
}

function stampAgent(id, extra) {
  try {
    writeAgent(id, Object.assign({ last: new Date().toISOString(), error: null }, extra || {}));
  } catch (e) {}
}

function buildAgents() {
  const now = new Date();
  const agents = CATALOG.map(cat => {
    const rd = readAgentFile(cat.id);
    if (!rd.ok) {
      return Object.assign({}, cat, {
        last: null, age_min: null, next_in_min: null, phase: 0,
        state: "error", metric: "", detail: "falha ao ler " + cat.arquivo + ": " + rd.error, run: cat.run
      });
    }
    const rec = rd.data || {};
    const last = rec.last || null;
    const on = rec.on !== false;
    let state, age_min = null, next_in_min = null, phase = null;
    if (rec.on === false) {
      state = "off";
    } else if (rec.error) {
      state = "error";
    } else if (!last) {
      state = "idle";
    } else {
      age_min = Math.max(0, (now.getTime() - new Date(last).getTime()) / 60000);
      phase = Math.min(1, age_min / cat.every_min);
      next_in_min = Math.max(0, cat.every_min - age_min);
      state = age_min > cat.every_min * STALE_FACTOR ? "stale" : "ok";
    }
    return {
      id: cat.id,
      nome: cat.nome,
      icon: cat.icon,
      faz: cat.faz,
      every_min: cat.every_min,
      last: last,
      age_min: age_min,
      next_in_min: next_in_min,
      phase: phase,
      state: state,
      metric: rec.metric || "",
      detail: rec.error || rec.detail || "",
      run: cat.run,
      arquivo: cat.arquivo
    };
  });
  const resumo = { total: agents.length, ok: 0, atencao: 0, off: 0, pior: null };
  const rank = { error: 4, stale: 3, idle: 2, off: 1, ok: 0 };
  let worst = 0;
  agents.forEach(a => {
    if (a.state === "ok") resumo.ok++;
    else if (a.state === "off") resumo.off++;
    else resumo.atencao++;
    if ((rank[a.state] || 0) > worst) { worst = rank[a.state]; resumo.pior = a.id; }
  });
  return { ok: true, now: now.toISOString(), agents: agents, resumo: resumo };
}

async function runNoticias() {
  const topics = ["tecnologia", "economia"];
  let n = 0;
  for (let i = 0; i < topics.length; i++) {
    const q = topics[i];
    const url = "https://news.google.com/rss/search?q=" + encodeURIComponent(q) + "&hl=pt-BR&gl=BR&ceid=BR:pt-419";
    const xml = await fetchUrl(url, 3);
    n += (xml.match(/<item[\s>]/g) || xml.match(/<item>/g) || []).length;
  }
  writeAgent("noticias", {
    last: new Date().toISOString(),
    metric: n + " manchetes",
    detail: "radar atualizado",
    error: null,
    on: true
  });
}

function readBody(req, max) {
  const cap = max || 16 * 1024 * 1024;
  return new Promise((resolve, reject) => {
    const chunks = [];
    let n = 0;
    req.on("data", c => {
      n += c.length;
      if (n > cap) {
        req.destroy();
        const e = new Error("corpo grande demais");
        e.code = 413;
        reject(e);
        return;
      }
      chunks.push(c);
    });
    req.on("end", () => resolve(Buffer.concat(chunks).toString("utf8")));
    req.on("error", reject);
  });
}

function sendJson(res, code, obj) {
  send(res, code, JSON.stringify(obj), "application/json; charset=utf-8");
}

const DATA_DIR = path.join(__dirname, "data");
const CFG_PATH = path.join(DATA_DIR, "config.json");
const MIND_PATH = path.join(DATA_DIR, "mind.json");
const OLLAMA = { host: "127.0.0.1", port: 11434 };
const startedAt = Date.now();
let BRAIN = { ok: false, model: "", vision: "", names: [], at: 0 };

function ensureData() {
  fs.mkdirSync(DATA_DIR, { recursive: true });
  fs.mkdirSync(AGENT_DIR, { recursive: true });
  ensureVault();
}

function loadConfig() {
  try {
    return JSON.parse(fs.readFileSync(CFG_PATH, "utf8"));
  } catch (e) {
    return { cals: [], mail: [] };
  }
}

function saveConfig(next) {
  ensureData();
  const prev = loadConfig();
  const out = {
    cals: Array.isArray(next.cals) ? next.cals : prev.cals || [],
    mail: Array.isArray(next.mail) ? next.mail : prev.mail || [],
    city: next.city != null ? String(next.city) : (prev.city || "São Paulo")
  };
  writeJson(CFG_PATH, out);
  return out;
}

function publicConfig() {
  const c = loadConfig();
  return {
    cals: (c.cals || []).map(x => ({ id: x.id, name: x.name, color: x.color, url: x.url || "" })),
    mail: (c.mail || []).map(x => ({
      id: x.id, nick: x.nick, color: x.color, host: x.host || "imap.gmail.com",
      user: x.user || "", pass: x.pass ? "********" : "", hasPass: !!x.pass
    })),
    city: c.city || "São Paulo"
  };
}

function ollamaReq(method, pathname, body, timeoutMs) {
  return new Promise((resolve, reject) => {
    const data = body == null ? null : JSON.stringify(body);
    const req = http.request({
      hostname: OLLAMA.host,
      port: OLLAMA.port,
      path: pathname,
      method: method,
      headers: data ? { "Content-Type": "application/json", "Content-Length": Buffer.byteLength(data) } : {}
    }, rec => {
      const chunks = [];
      rec.on("data", c => chunks.push(c));
      rec.on("end", () => {
        const raw = Buffer.concat(chunks).toString("utf8");
        if (rec.statusCode >= 400) {
          const err = new Error("ollama " + rec.statusCode);
          err.code = rec.statusCode >= 500 ? 502 : rec.statusCode;
          reject(err);
          return;
        }
        try { resolve(raw ? JSON.parse(raw) : {}); }
        catch (e) { reject(new Error("ollama json")); }
      });
    });
    req.on("error", reject);
    req.setTimeout(timeoutMs || 20000, () => { req.destroy(new Error("timeout ollama")); });
    if (data) req.end(data);
    else req.end();
  });
}

function pickModels(names) {
  const vision = names.find(n => /llava|llama3\.2-vision|qwen2\.5-vl|qwen2-vl|bakllava|moondream|minicpm-v|gemma3/i.test(n)) || "";
  const coder = names.find(n => /coder|codellama|deepseek-coder/i.test(n)) || "";
  const chatPrefer = ["llama3.2", "llama3.1", "llama3", "qwen2.5", "qwen2", "mistral", "phi3", "gemma2", "gemma"];
  const chat = chatPrefer.map(p => names.find(n => n.indexOf(p) === 0 && n.indexOf("vision") < 0 && n.indexOf("coder") < 0)).find(Boolean)
    || names.find(n => n.indexOf("vision") < 0 && n.indexOf("coder") < 0)
    || names[0] || "";
  return { model: chat, chat: chat, coder: coder, vision: vision };
}

async function refreshBrain(force) {
  if (!force && BRAIN.at && Date.now() - BRAIN.at < 30000 && BRAIN.ok) return BRAIN;
  try {
    const d = await ollamaReq("GET", "/api/tags", null, 4000);
    const names = (d.models || []).map(m => m.name);
    if (!names.length) throw new Error("sem modelos");
    const pick = pickModels(names);
    BRAIN = { ok: true, model: pick.model, chat: pick.chat, coder: pick.coder, vision: pick.vision, names: names, at: Date.now() };
  } catch (e) {
    BRAIN = { ok: false, model: BRAIN.model || "", chat: BRAIN.chat || "", coder: BRAIN.coder || "", vision: BRAIN.vision || "", names: BRAIN.names || [], at: Date.now() };
  }
  return BRAIN;
}

async function askBrain(body) {
  const brain = await refreshBrain(false);
  if (!brain.ok) {
    const e = new Error("Ollama offline — abra o app ou rode ollama serve");
    e.code = 503;
    throw e;
  }
  const images = Array.isArray(body.images) ? body.images.filter(Boolean).slice(0, 2) : [];
  const img = images.length > 0 || body.intent === "vision";
  const model = String(body.model || (img ? brain.vision : (body.intent === "code" ? (brain.coder || brain.model) : (brain.chat || brain.model))) || "");
  if (img && !brain.vision && !body.model) {
    const e = new Error("sem modelo de visão — ollama pull moondream");
    e.code = 503;
    throw e;
  }
  const prompt = String(body.prompt || "");
  const messages = Array.isArray(body.messages) ? body.messages.slice() : [];
  const steer = "Responda só o pedido, em português do Brasil, 2 a 6 frases. Sem markdown. Não invente.";
  if (!img && body.intent !== "analyze" && messages.length) {
    const sys = messages.find(m => m.role === "system");
    if (sys && String(sys.content).indexOf("Raciocine em silêncio") < 0) sys.content += "\n" + steer;
    else if (!sys) messages.unshift({ role: "system", content: steer });
  }
  if (img) {
    const moon = /moondream/i.test(model);
    if (!moon) {
      try {
        const chat = await ollamaReq("POST", "/api/chat", {
          model: model,
          stream: false,
          keep_alive: "30m",
          options: { temperature: 0.3, top_p: 0.9, num_predict: 220 },
          messages: messages.length
            ? messages
            : [{ role: "user", content: prompt || "analise a imagem", images: images }]
        }, 90000);
        const out = (chat.message && chat.message.content) || "";
        if (out) return { text: out, model: model, vision: true };
      } catch (e) {}
    }
    const gen = await ollamaReq("POST", "/api/generate", {
      model: model,
      prompt: prompt || "analise a imagem",
      images: images,
      stream: false,
      keep_alive: "30m"
    }, 90000);
    return { text: gen.response || "", model: model, vision: true };
  }
  const code = body.intent === "code";
  const chat = await ollamaReq("POST", "/api/chat", {
    model: model,
    stream: false,
    keep_alive: "10m",
    options: { temperature: code ? 0.28 : 0.48, top_p: 0.9, num_predict: code ? 480 : 280 },
    messages: messages.length ? messages : [{ role: "user", content: prompt || "olá" }]
  }, code ? 40000 : 25000);
  return { text: (chat.message && chat.message.content) || "", model: model, vision: false };
}

function vaultStats() {
  try {
    const list = listVault("");
    return { ok: true, files: (list.items || []).length };
  } catch (e) {
    return { ok: false, files: 0 };
  }
}

async function runAgenda() {
  const urls = (loadConfig().cals || []).map(c => String(c.url || "").replace(/^webcal:/i, "https:")).filter(Boolean);
  if (!urls.length) {
    stampAgent("agenda", { on: false, detail: "sem link iCal", error: null });
    return { n: 0 };
  }
  let n = 0;
  const errs = [];
  for (let i = 0; i < urls.length; i++) {
    try {
      const ics = await fetchUrl(urls[i], 4);
      if (ics.indexOf("BEGIN:VCALENDAR") < 0) throw new Error("ics");
      n += (ics.match(/BEGIN:VEVENT/g) || []).length;
    } catch (e) {
      errs.push(String(e.message || e));
    }
  }
  stampAgent("agenda", {
    metric: n + " eventos",
    detail: errs.length ? "falha em agenda" : "timeline ok",
    error: errs.length ? errs[0] : null,
    on: true
  });
  return { n: n, errs: errs };
}

async function runEmails() {
  const accs = (loadConfig().mail || []).filter(a => a.user && a.pass);
  if (!accs.length) {
    stampAgent("emails", { on: false, detail: "sem senha de app", error: null });
    return { n: 0 };
  }
  let n = 0;
  const errs = [];
  for (let i = 0; i < accs.length; i++) {
    const a = accs[i];
    try {
      const list = await fetchEmails(a.host || "imap.gmail.com", a.user, a.pass, 20);
      n += list.length;
    } catch (e) {
      errs.push(String(e.message || e));
    }
  }
  stampAgent("emails", {
    metric: n + " lidos",
    detail: errs.length ? "falha em conta" : "caixa examinada",
    error: errs.length ? "falha de login" : null,
    on: true
  });
  return { n: n, errs: errs };
}

let tickBusy = false;
async function tickHub() {
  if (tickBusy) return;
  tickBusy = true;
  try {
  const snap = buildAgents();
  for (let i = 0; i < snap.agents.length; i++) {
    const a = snap.agents[i];
    if (a.state === "off") continue;
    const stale = a.state === "idle" || a.state === "stale" || a.state === "error";
    if (!stale) continue;
    try {
      if (a.id === "noticias") await runNoticias();
      else if (a.id === "agenda") await runAgenda();
      else if (a.id === "emails") await runEmails();
    } catch (e) {
      stampAgent(a.id, { error: String(e.message || e).slice(0, 160) });
    }
  }
  } finally { tickBusy = false; }
}

const server = http.createServer(async (req, res) => {
  cors(res);
  if (req.method === "OPTIONS") {
    res.writeHead(204);
    res.end();
    return;
  }
  let u;
  try { u = new URL(req.url, "http://127.0.0.1"); } catch (e) {
    send(res, 400, "URL inválida");
    return;
  }
  try {
    if (req.method === "GET" && (u.pathname === "/" || u.pathname === "/fenix.html")) {
      const file = path.join(__dirname, "fenix.html");
      let html;
      try { html = fs.readFileSync(file, "utf8"); } catch (e) {
        send(res, 404, "fenix.html não encontrado");
        return;
      }
      send(res, 200, html, "text/html; charset=utf-8");
      return;
    }
    if (req.method === "GET" && (u.pathname === "/fenix-knight.png" || u.pathname === "/fenix-realm.png" || u.pathname === "/fenix-skull.png" || u.pathname === "/fenix-icon.png")) {
      const img = path.join(__dirname, path.basename(u.pathname));
      let buf;
      try { buf = fs.readFileSync(img); } catch (e) {
        send(res, 404, "imagem não encontrada");
        return;
      }
      cors(res);
      res.writeHead(200, { "Content-Type": "image/png", "Content-Length": buf.length, "Cache-Control": "no-store" });
      res.end(buf);
      return;
    }
    if (req.method === "GET" && u.pathname === "/proxy") {
      const target = String(u.searchParams.get("url") || "").trim().replace(/^webcal:/i, "https:");
      let parsed;
      try { parsed = new URL(target); } catch (e) {
        send(res, 400, "URL inválida");
        return;
      }
      console.log("proxy " + parsed.hostname);
      const text = await fetchUrl(target, 3);
      if (parsed.hostname === "calendar.google.com") stampAgent("agenda", { metric: "ics lido", detail: "agenda sincronizada", on: true });
      if (parsed.hostname === "news.google.com" || parsed.hostname === "www.google.com") stampAgent("noticias", { metric: "rss lido", detail: "radar sincronizado", on: true });
      send(res, 200, text, "text/plain; charset=utf-8");
      return;
    }
    if (req.method === "GET" && u.pathname === "/api/health") {
      const brain = await refreshBrain(false);
      sendJson(res, 200, {
        ok: true,
        port: PORT,
        uptime: Math.round((Date.now() - startedAt) / 1000),
        ollama: { ok: brain.ok, model: brain.model, chat: brain.chat, coder: brain.coder, vision: brain.vision },
        vault: vaultStats(),
        agents: buildAgents().resumo
      });
      return;
    }
    if (req.method === "GET" && u.pathname === "/api/brain") {
      const brain = await refreshBrain(true);
      sendJson(res, brain.ok ? 200 : 503, { ok: brain.ok, model: brain.model, chat: brain.chat, coder: brain.coder, vision: brain.vision, names: brain.names || [] });
      return;
    }
    if (req.method === "POST" && u.pathname === "/api/brain") {
      const raw = await readBody(req, 8 * 1024 * 1024);
      let body;
      try { body = JSON.parse(raw || "{}"); } catch (e) { sendJson(res, 400, { ok: false, error: "JSON inválido" }); return; }
      const out = await askBrain(body || {});
      sendJson(res, 200, { ok: true, text: out.text, model: out.model, vision: !!out.vision });
      return;
    }
    if (req.method === "GET" && u.pathname === "/api/mind") {
      try {
        sendJson(res, 200, { ok: true, mind: JSON.parse(fs.readFileSync(MIND_PATH, "utf8")) });
      } catch (e) {
        sendJson(res, 200, { ok: true, mind: { episodes: [], history: [] } });
      }
      return;
    }
    if (req.method === "POST" && u.pathname === "/api/mind") {
      const raw = await readBody(req);
      let body;
      try { body = JSON.parse(raw || "{}"); } catch (e) { sendJson(res, 400, { ok: false, error: "JSON inválido" }); return; }
      ensureData();
      const prev = (() => { try { return JSON.parse(fs.readFileSync(MIND_PATH, "utf8")); } catch (e) { return {}; } })();
      const next = {
        episodes: Array.isArray(body.episodes) ? body.episodes.slice(-80) : prev.episodes || [],
        history: Array.isArray(body.history) ? body.history.slice(-24) : prev.history || [],
        intent: body.intent || prev.intent || "chat",
        analysis: String(body.analysis || prev.analysis || "").slice(0, 400),
        t: Date.now()
      };
      writeJson(MIND_PATH, next);
      sendJson(res, 200, { ok: true });
      return;
    }
    if (req.method === "GET" && u.pathname === "/api/config") {
      sendJson(res, 200, { ok: true, config: publicConfig() });
      return;
    }
    if (req.method === "POST" && u.pathname === "/api/config") {
      const raw = await readBody(req);
      let body;
      try { body = JSON.parse(raw || "{}"); } catch (e) { sendJson(res, 400, { ok: false, error: "JSON inválido" }); return; }
      const prev = loadConfig();
      const mail = Array.isArray(body.mail) ? body.mail.map(function (a) {
        const old = (prev.mail || []).find(x => x.id === a.id) || {};
        const pass = String(a.pass || "");
        return {
          id: a.id,
          nick: a.nick,
          color: a.color,
          host: a.host || "imap.gmail.com",
          user: String(a.user || "").trim(),
          pass: !pass || pass.indexOf("*") === 0 ? (old.pass || "") : pass.replace(/\s+/g, "")
        };
      }) : prev.mail;
      const saved = saveConfig({
        cals: Array.isArray(body.cals) ? body.cals : prev.cals,
        mail: mail,
        city: body.city
      });
      sendJson(res, 200, { ok: true, config: publicConfig(), saved: !!saved });
      return;
    }
    if (req.method === "GET" && u.pathname === "/api/agents") {
      send(res, 200, JSON.stringify(buildAgents()), "application/json; charset=utf-8");
      return;
    }
    if (req.method === "POST" && u.pathname === "/api/agents/beat") {
      const raw = await readBody(req);
      let body;
      try { body = JSON.parse(raw); } catch (e) { send(res, 400, "JSON inválido"); return; }
      const id = String(body.id || "");
      if (!CATALOG.some(c => c.id === id)) { send(res, 400, "agente desconhecido"); return; }
      const patch = { on: body.on !== false };
      if (body.last) patch.last = body.last;
      else if (body.on !== false) patch.last = new Date().toISOString();
      if (body.metric != null) patch.metric = String(body.metric).slice(0, 80);
      if (body.detail != null) patch.detail = String(body.detail).slice(0, 160);
      if (body.error) patch.error = String(body.error).slice(0, 160);
      else patch.error = null;
      writeAgent(id, patch);
      send(res, 200, JSON.stringify({ ok: true }), "application/json; charset=utf-8");
      return;
    }
    if (req.method === "POST" && u.pathname === "/api/agents/run") {
      const raw = await readBody(req);
      let body;
      try { body = JSON.parse(raw); } catch (e) { send(res, 400, "JSON inválido"); return; }
      if (body.id === "noticias") await runNoticias();
      else if (body.id === "agenda") await runAgenda();
      else if (body.id === "emails") await runEmails();
      else {
        sendJson(res, 400, { ok: false, error: "este agente não tem execução no servidor" });
        return;
      }
      send(res, 200, JSON.stringify({ ok: true, agents: buildAgents() }), "application/json; charset=utf-8");
      return;
    }
    if (req.method === "GET" && u.pathname === "/api/vault") {
      send(res, 200, JSON.stringify(listVault(u.searchParams.get("dir") || "")), "application/json; charset=utf-8");
      return;
    }
    if (req.method === "GET" && u.pathname === "/api/vault/read") {
      send(res, 200, JSON.stringify(peekVault(u.searchParams.get("path") || "")), "application/json; charset=utf-8");
      return;
    }
    if (req.method === "GET" && u.pathname === "/api/vault/find") {
      send(res, 200, JSON.stringify(findVault(u.searchParams.get("q") || "", u.searchParams.get("kind") || "")), "application/json; charset=utf-8");
      return;
    }
    if (req.method === "GET" && u.pathname === "/api/vault/file") {
      const rel = u.searchParams.get("path") || "";
      const abs = vaultAbs(rel);
      if (!fs.existsSync(abs) || fs.statSync(abs).isDirectory()) {
        send(res, 404, "arquivo não encontrado");
        return;
      }
      const buf = fs.readFileSync(abs);
      const ext = path.extname(abs).toLowerCase();
      const mime = MIME[ext] || (sniffImage(buf) ? "image/jpeg" : "application/octet-stream");
      cors(res);
      res.writeHead(200, {
        "Content-Type": mime,
        "Content-Length": buf.length,
        "Cache-Control": "no-store"
      });
      res.end(buf);
      return;
    }
    if (req.method === "POST" && u.pathname === "/api/vault/mkdir") {
      const raw = await readBody(req);
      let body;
      try { body = JSON.parse(raw); } catch (e) { send(res, 400, "JSON inválido"); return; }
      const parent = String(body.dir || "");
      const name = String(body.name || "").replace(/[\\/:*?"<>|]/g, "").trim();
      if (!name) { send(res, 400, "nome inválido"); return; }
      const target = vaultAbs(parent ? parent + "/" + name : name);
      ensureVault();
      fs.mkdirSync(target, { recursive: true });
      send(res, 200, JSON.stringify(listVault(parent)), "application/json; charset=utf-8");
      return;
    }
    if (req.method === "POST" && u.pathname === "/api/vault/upload") {
      const raw = await readBody(req);
      if (raw.length > 14 * 1024 * 1024) { send(res, 413, "arquivo grande demais"); return; }
      let body;
      try { body = JSON.parse(raw); } catch (e) { send(res, 400, "JSON inválido"); return; }
      const parent = String(body.dir || "");
      const name = String(body.name || "").replace(/[\\/:*?"<>|]/g, "").trim();
      if (!name) { send(res, 400, "nome inválido"); return; }
      const b64 = String(body.data || "").replace(/^data:[^;]+;base64,/, "");
      const buf = Buffer.from(b64, "base64");
      if (!buf.length) { send(res, 400, "arquivo vazio"); return; }
      ensureVault();
      fs.writeFileSync(vaultAbs(parent ? parent + "/" + name : name), buf);
      send(res, 200, JSON.stringify(listVault(parent)), "application/json; charset=utf-8");
      return;
    }
    if (req.method === "POST" && (u.pathname === "/emails" || u.pathname === "/api/emails")) {
      const raw = await readBody(req);
      let body;
      try { body = JSON.parse(raw); } catch (e) {
        send(res, 400, "JSON inválido");
        return;
      }
      const host = String(body.host || "imap.gmail.com");
      const usuario = String(body.usuario || "");
      const senhaApp = String(body.senhaApp || "");
      const quantidade = body.quantidade;
      console.log("IMAP " + host + " conta ***");
      const list = await fetchEmails(host, usuario, senhaApp, quantidade);
      stampAgent("emails", { metric: list.length + " lidos", detail: "caixa examinada", on: true });
      send(res, 200, JSON.stringify(list), "application/json; charset=utf-8");
      return;
    }
    send(res, 404, "não encontrado");
  } catch (err) {
    const api = u && u.pathname && u.pathname.indexOf("/api/") === 0;
    if (err.code === 413) { send(res, 413, "arquivo grande demais"); return; }
    if (err.code === 404) { send(res, 404, err.message || "não encontrado"); return; }
    if (err.code === 403) { send(res, 403, err.message || "proibido"); return; }
    if (err.code === 401) {
      send(res, 401, "Senha de app inválida ou 2 etapas desativada — refaça em myaccount.google.com/apppasswords");
      return;
    }
    if (err.code === 503) {
      if (api) sendJson(res, 503, { ok: false, error: err.message || "serviço indisponível" });
      else send(res, 503, err.message || "serviço indisponível");
      return;
    }
    console.log("antena", err.message || err);
    if (api) sendJson(res, 502, { ok: false, error: err.message || "falha na antena" });
    else send(res, 502, "falha na antena");
  }
});

server.on("error", err => {
  if (err.code === "EADDRINUSE") {
    console.log("A porta " + PORT + " já está em uso. Feche o outro Fenix e tente de novo.");
  } else {
    console.log("Falha ao subir a antena.");
  }
  process.exit(1);
});

if (process.argv.indexOf("--selftest") >= 0) {
  runNoticias().then(() => {
    const before = buildAgents();
    const n = before.agents.find(a => a.id === "noticias");
    console.log("noticias last", n.last, "state", n.state, "metric", n.metric);
    process.exit(n.last ? 0 : 1);
  }).catch(e => {
    console.error("selftest", e.message || e);
    process.exit(1);
  });
} else {
  ensureData();
  server.requestTimeout = 120000;
  server.headersTimeout = 125000;
  server.listen(PORT, HOST, () => {
    console.log("⚡ ANTENA DO FENIX ONLINE — porta " + PORT + " — http://127.0.0.1:" + PORT + "/");
    refreshBrain(true).then(function (b) {
      console.log(b.ok ? ("cérebro · " + b.model + (b.vision ? " · visão " + b.vision : "")) : "cérebro · ollama offline");
    }).catch(function () {});
    setTimeout(function () { tickHub().catch(function () {}); }, 4000);
    setInterval(function () { tickHub().catch(function () {}); }, 5 * 60 * 1000);
  });
}
