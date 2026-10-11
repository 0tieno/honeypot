// Cloud Bait presenter: live honeypot stats as full-screen slides.
//
// Runs on your laptop only (binds 127.0.0.1). Reuses your `az login`, but asks for a token whose
// audience is the Log Analytics *query* API, so it can read logs and nothing else. No secrets on disk.
// Every successful refresh is saved to .snapshot.json, which keeps the slides working if Wi-Fi dies.
//
// Usage: node presenter/server.js   then open http://localhost:4000

"use strict";
const http = require("http");
const fs = require("fs");
const path = require("path");
const { execFile } = require("child_process");

const PORT = Number(process.env.PORT || 4000);
const HOST = "127.0.0.1";
const RG = "cloud-bait-rg";
const WORKSPACE = "cb-law";
const REFRESH_MS = 30_000;
const STALE_MS = 2 * 60_000;
const ROOT = path.join(__dirname, "..");
const SNAPSHOT = path.join(__dirname, ".snapshot.json");
const INDEX = path.join(__dirname, "index.html");

// ---------- az CLI helpers ----------
function az(args) {
  return new Promise((resolve, reject) => {
    execFile("az", args, { shell: process.platform === "win32", timeout: 60_000, windowsHide: true },
      (err, stdout, stderr) => (err ? reject(new Error((stderr || err.message).trim())) : resolve(stdout.trim())));
  });
}

let token = null; // { value, expiresAt }
async function getToken() {
  if (token && token.expiresAt - Date.now() > 5 * 60_000) return token.value;
  const out = JSON.parse(await az(["account", "get-access-token", "--resource", "https://api.loganalytics.io", "-o", "json"]));
  const exp = out.expires_on ? Number(out.expires_on) * 1000 : Date.parse(out.expiresOn);
  token = { value: out.accessToken, expiresAt: exp || Date.now() + 30 * 60_000 };
  return token.value;
}

let workspaceId = process.env.CB_WORKSPACE_ID || null;
async function getWorkspaceId() {
  if (!workspaceId) workspaceId = await az(["monitor", "log-analytics", "workspace", "show", "-g", RG, "-n", WORKSPACE, "--query", "customerId", "-o", "tsv"]);
  return workspaceId;
}

// ---------- KQL ----------
// Reuse the shared header from queries/ so the exclusion list and exposure time have one source of truth.
function header() {
  const text = fs.readFileSync(path.join(ROOT, "queries", "01_total_activity.kql"), "utf8");
  return text.split(/\r?\n/).filter(l => l.startsWith("let ")).join("\n");
}

const SVC = `extend Service=iif(DstPort==2223,"Telnet","SSH")`;
const QUERIES = {
  totals: `union
 (ssh | where EventId == "cowrie.session.connect" | summarize n=count() | extend k="sessions"),
 (ssh | where EventId in ("cowrie.login.success","cowrie.login.failed") | summarize n=count() | extend k="logins"),
 (ssh | where EventId == "cowrie.command.input" | summarize n=count() | extend k="commands"),
 (ssh | summarize n=count() | extend k="sshEvents"),
 (web | summarize n=count() | extend k="http"),
 (union ssh, web | summarize n=dcount(SrcIp) | extend k="ips")
| project k, n`,
  first: `union (ssh | ${SVC}), (web | extend Service=iif(Scheme=="https","HTTPS","HTTP"))
| top 1 by TimeGenerated asc
| project First=TimeGenerated, Service, SrcIp, Exposed=exposed`,
  exposed: `print Exposed=exposed`,
  hourly: `union (ssh | where EventId == "cowrie.session.connect" | ${SVC}), (web | extend Service="Web")
| summarize n=count() by Service, Hour=bin(TimeGenerated, 1h)
| order by Hour asc`,
  usernames: `ssh | where EventId in ("cowrie.login.success","cowrie.login.failed")
| summarize n=count() by Username | top 8 by n desc`,
  passwords: `ssh | where EventId in ("cowrie.login.success","cowrie.login.failed")
| summarize n=count() by Password | top 8 by n desc`,
  urls: `web | summarize n=count(), ips=dcount(SrcIp) by UrlPath | top 10 by n desc`,
  commands: `ssh | where EventId == "cowrie.command.input" and isnotempty(trim(@"\\s+", Command))
| summarize n=count(), ips=dcount(SrcIp) by Command | top 8 by n desc`,
  countries: `union (ssh | where EventId == "cowrie.session.connect"), web
| summarize n=count() by SrcIp
| extend Country = tostring(geo_info_from_ip_address(SrcIp).country)
| summarize n=sum(n), ips=count() by Country
| where isnotempty(Country)
| order by n desc`,
  feed: `union
 (ssh | where EventId in ("cowrie.login.success","cowrie.login.failed","cowrie.command.input")
      or EventId startswith "cowrie.session.file_download"
      | ${SVC}
      | project TimeGenerated, SrcIp, Kind=case(EventId=="cowrie.command.input","cmd", EventId startswith "cowrie.login","login","download"),
                What=case(EventId=="cowrie.command.input", Command, EventId startswith "cowrie.login", strcat(Username, " / ", Password), Url), Service),
 (web | project TimeGenerated, SrcIp, Kind="web", What=strcat(Method, " ", UrlPath), Service=toupper(Scheme))
| top 14 by TimeGenerated desc`,
};

async function runQuery(kql) {
  const [tok, ws] = [await getToken(), await getWorkspaceId()];
  const res = await fetch(`https://api.loganalytics.io/v1/workspaces/${ws}/query`, {
    method: "POST",
    headers: { Authorization: `Bearer ${tok}`, "Content-Type": "application/json" },
    body: JSON.stringify({ query: `${header()}\n${kql}` }),
    signal: AbortSignal.timeout(45_000),
  });
  if (!res.ok) throw new Error(`HTTP ${res.status}: ${(await res.text()).slice(0, 300)}`);
  const t = (await res.json()).tables[0];
  return t.rows.map(r => Object.fromEntries(t.columns.map((c, i) => [c.name, r[i]])));
}

// ---------- privacy ----------
// Attacker IPs are often hijacked home machines: show only the first two octets on screen.
const maskIp = ip => (typeof ip === "string" && /^\d+\.\d+\.\d+\.\d+$/.test(ip) ? ip.split(".").slice(0, 2).join(".") + ".x.x" : "hidden");
function scrub(name, rows) {
  if (name === "first" || name === "feed") return rows.map(r => ({ ...r, SrcIp: maskIp(r.SrcIp) }));
  return rows;
}

// ---------- state ----------
let state = { data: {}, updatedAt: null, lastError: null, lastAttemptAt: null };
try { state = { ...state, ...JSON.parse(fs.readFileSync(SNAPSHOT, "utf8")), lastError: null }; } catch { /* first run */ }

let refreshing = false;
async function refresh() {
  if (refreshing) return;
  refreshing = true;
  state.lastAttemptAt = new Date().toISOString();
  const names = Object.keys(QUERIES);
  const results = await Promise.allSettled(names.map(n => runQuery(QUERIES[n])));
  let ok = 0;
  results.forEach((r, i) => {
    if (r.status === "fulfilled") { state.data[names[i]] = scrub(names[i], r.value); ok++; }
    else state.lastError = `${names[i]}: ${r.reason.message}`;
  });
  if (ok === names.length) {
    state.updatedAt = new Date().toISOString();
    state.lastError = null;
    fs.writeFile(SNAPSHOT, JSON.stringify({ data: state.data, updatedAt: state.updatedAt }), () => {});
  }
  console.log(`[${new Date().toLocaleTimeString()}] refresh ${ok}/${names.length} ok${state.lastError ? " - " + state.lastError : ""}`);
  refreshing = false;
}

// ---------- HTTP ----------
const server = http.createServer((req, res) => {
  const sec = { "X-Content-Type-Options": "nosniff", "Cache-Control": "no-store", "Referrer-Policy": "no-referrer" };
  if (req.method === "GET" && (req.url === "/" || req.url === "/index.html")) {
    res.writeHead(200, { ...sec, "Content-Type": "text/html; charset=utf-8",
      "Content-Security-Policy": "default-src 'self'; script-src 'self' 'unsafe-inline'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'" });
    return fs.createReadStream(INDEX).pipe(res);
  }
  if (req.method === "GET" && req.url === "/api/stats") {
    const live = state.updatedAt && !state.lastError && Date.now() - Date.parse(state.updatedAt) < STALE_MS;
    res.writeHead(200, { ...sec, "Content-Type": "application/json" });
    return res.end(JSON.stringify({ ...state, live: Boolean(live), now: new Date().toISOString() }));
  }
  res.writeHead(404, sec);
  res.end("not found");
});

server.listen(PORT, HOST, () => {
  console.log(`Cloud Bait presenter on http://localhost:${PORT}  (local only, refresh every ${REFRESH_MS / 1000}s)`);
  if (state.updatedAt) console.log(`Loaded offline snapshot from ${state.updatedAt}`);
  refresh();
  setInterval(refresh, REFRESH_MS);
});
