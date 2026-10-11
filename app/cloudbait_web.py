#!/usr/bin/env python3
"""Cloud Bait fake web application.

A deliberately boring-but-tempting fake corporate portal for "Kipeo Digital
Services" (fictional). Every response is synthetic. Every request is logged as
one JSON line to LOG_PATH for Azure Monitor Agent to pick up.

Runs behind nginx (which terminates TLS and sets X-Forwarded-For / X-Forwarded-Proto).
Standard library only, so there is nothing to pip install on the honeypot.
"""

import json
import os
import sys
from datetime import datetime, timezone
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlsplit

LOG_PATH = os.environ.get("CLOUDBAIT_LOG", "/var/log/cloudbait/web.json")
LISTEN_HOST = os.environ.get("CLOUDBAIT_HOST", "127.0.0.1")
LISTEN_PORT = int(os.environ.get("CLOUDBAIT_PORT", "8080"))
MAX_BODY_LOG = 4096
SERVER_BANNER = "nginx/1.18.0 (Ubuntu)"

COMPANY = "Kipeo Digital Services"

PAGE = """<!doctype html>
<html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>{title} | {company}</title>
<style>
body{{margin:0;font-family:Segoe UI,Helvetica,Arial,sans-serif;background:#f4f6f9;color:#1d2733}}
header{{background:#0d3b66;color:#fff;padding:18px 32px;display:flex;justify-content:space-between;align-items:center}}
header b{{font-size:20px;letter-spacing:1px}} header nav a{{color:#cfe3f7;margin-left:18px;text-decoration:none}}
main{{max-width:960px;margin:32px auto;padding:0 16px}}
.card{{background:#fff;border-radius:8px;box-shadow:0 1px 3px rgba(0,0,0,.12);padding:24px;margin-bottom:20px}}
.btn{{display:inline-block;background:#0d3b66;color:#fff;padding:10px 18px;border-radius:5px;text-decoration:none;margin:6px 8px 6px 0;border:0;cursor:pointer}}
.ok{{color:#1a7f37;font-weight:600}} table{{border-collapse:collapse;width:100%}}
td,th{{text-align:left;padding:8px;border-bottom:1px solid #e5e8ec}} input{{padding:9px;width:100%;box-sizing:border-box;margin:6px 0 12px;border:1px solid #c5ccd5;border-radius:4px}}
footer{{text-align:center;color:#7a8592;font-size:12px;padding:24px}}
</style></head><body>
<header><b>KIPEO DIGITAL SERVICES</b><nav><a href="/">Home</a><a href="/login">Customer Portal</a><a href="/admin">Administration</a><a href="/api">API Docs</a></nav></header>
<main>{body}</main>
<footer>&copy; 2026 {company} &middot; Secure Business Platform v3.4.1 &middot; build 20260918-prod</footer>
</body></html>"""

HOME = """
<div class="card"><h1>Secure Business Platform</h1>
<p>Payments, customer records and analytics for East African SMEs.</p>
<a class="btn" href="/login">Customer Portal</a><a class="btn" href="/admin">Administration</a><a class="btn" href="/api">API Documentation</a>
<p>System Status: <span class="ok">&#9679; Operational</span></p></div>
<div class="card"><h3>Cloud Environment</h3><table>
<tr><th>Component</th><th>Resource</th><th>Status</th></tr>
<tr><td>Production API</td><td>api-prod</td><td class="ok">Healthy</td></tr>
<tr><td>Database</td><td>postgres-prod</td><td class="ok">Healthy</td></tr>
<tr><td>Storage</td><td>customer-storage</td><td class="ok">Healthy</td></tr>
<tr><td>Admin Portal</td><td>admin-prod</td><td class="ok">Healthy</td></tr>
<tr><td>Backup</td><td>backup-prod</td><td class="ok">Last run 02:00 EAT</td></tr>
</table></div>"""

LOGIN = """
<div class="card" style="max-width:420px;margin:auto"><h2>{heading}</h2>{msg}
<form method="post" action="{action}">
<label>Username</label><input name="username" autocomplete="username">
<label>Password</label><input name="password" type="password" autocomplete="current-password">
<button class="btn" type="submit">Sign in</button></form></div>"""

API_DOCS = """
<div class="card"><h2>Kipeo Platform API v1</h2>
<p>Authenticate with <code>Authorization: Bearer &lt;token&gt;</code>.</p>
<table><tr><th>Method</th><th>Endpoint</th><th>Description</th></tr>
<tr><td>GET</td><td>/api/v1/users</td><td>List platform users</td></tr>
<tr><td>GET</td><td>/api/v1/customers</td><td>Customer records</td></tr>
<tr><td>GET</td><td>/api/v1/transactions</td><td>Transaction ledger</td></tr>
<tr><td>GET</td><td>/api/v1/admin</td><td>Administrative operations</td></tr>
<tr><td>POST</td><td>/api/v1/auth/token</td><td>Obtain access token</td></tr>
</table></div>"""

# --- Synthetic files. Nothing here is real: no people, no phones, no emails, no secrets. ---
FAKE_FILES = {
    "/.env": ("text/plain",
              "APP_ENV=demo\nAPP_NAME=cloud-bait\nAPP_DEBUG=false\n"
              "DATABASE_HOST=database.internal\nDATABASE_PORT=5432\nDATABASE_NAME=demo_database\n"
              "CACHE_DRIVER=redis\nREDIS_HOST=cache.internal\nLOG_CHANNEL=stack\n"),
    "/config.json": ("application/json", json.dumps({
        "environment": "production", "region": "eastafrica-1", "api": "api-prod",
        "database": {"host": "postgres-prod.internal", "name": "demo_database"},
        "storage": {"container": "customer-storage"}, "backup": {"target": "backup-prod", "schedule": "0 2 * * *"},
    }, indent=2) + "\n"),
    "/backup/backup_2026.sql": ("application/sql",
                                "-- Kipeo demo database dump\n-- generated 2026-09-30 02:00:01\n"
                                "CREATE TABLE customers (customer_id INTEGER PRIMARY KEY, tier TEXT);\n"
                                "INSERT INTO customers VALUES (100001,'gold'),(100002,'silver'),(100003,'bronze');\n"),
    "/backup/customer_export.csv": ("text/csv", "CUSTOMER_ID,TIER,REGION\n100001,gold,R1\n100002,silver,R2\n100003,bronze,R3\n"),
    "/backup/employee_list.csv": ("text/csv", "EMPLOYEE_ID,DEPARTMENT\nE-0001,Engineering\nE-0002,Finance\nE-0003,Support\n"),
    "/backup/transactions.csv": ("text/csv", "TXN_ID,CUSTOMER_ID,AMOUNT\nT-900001,100001,1500\nT-900002,100002,320\nT-900003,100003,75\n"),
}

DIR_LISTINGS = {
    "/backup": ["backup_2026.sql", "customer_export.csv", "employee_list.csv", "transactions.csv"],
    "/uploads": ["invoice_template.pdf", "logo.png"],
}


def api_payload(path):
    resource = path.rstrip("/").rsplit("/", 1)[-1]
    counts = {"users": 1384, "customers": 12482, "transactions": 98311, "admin": 7}
    if resource in counts:
        sample = [{"id": 100001 + i} for i in range(3)]
        return 200, {"status": "success", "environment": "production",
                     "resource": resource, "records": counts[resource], "data": sample}
    if resource in ("v1", "api"):
        return 200, {"status": "success", "version": "1.4.2",
                     "endpoints": ["/api/v1/users", "/api/v1/customers", "/api/v1/transactions", "/api/v1/admin"]}
    return 404, {"status": "error", "message": "resource not found"}


class Handler(BaseHTTPRequestHandler):
    server_version = SERVER_BANNER
    sys_version = ""
    protocol_version = "HTTP/1.1"

    # Silence the default stderr access log; we write our own JSON log.
    def log_message(self, fmt, *args):
        pass

    def client_ip(self):
        xff = self.headers.get("X-Forwarded-For", "")
        return xff.split(",")[0].strip() if xff else self.client_address[0]

    def read_body(self):
        try:
            length = min(int(self.headers.get("Content-Length", "0") or 0), 65536)
        except ValueError:
            length = 0
        return self.rfile.read(length) if length > 0 else b""

    def write_log(self, status, size, body):
        parts = urlsplit(self.path)
        record = {
            "timestamp": datetime.now(timezone.utc).isoformat(timespec="milliseconds").replace("+00:00", "Z"),
            "src_ip": self.client_ip(),
            "method": self.command,
            "uri": self.path[:2048],
            "path": parts.path[:1024],
            "query": parts.query[:1024],
            "status": status,
            "response_bytes": size,
            "request_bytes": int(self.headers.get("Content-Length", "0") or 0) if self.headers.get("Content-Length", "").isdigit() else 0,
            "user_agent": self.headers.get("User-Agent", "")[:512],
            "host": self.headers.get("Host", "")[:256],
            "scheme": self.headers.get("X-Forwarded-Proto", "http"),
            "referer": self.headers.get("Referer", "")[:512],
            "body": body[:MAX_BODY_LOG].decode("utf-8", "replace") if body else "",
        }
        if self.command == "POST" and body:
            form = parse_qs(body.decode("utf-8", "replace"))
            if "username" in form or "password" in form:
                record["login_username"] = form.get("username", [""])[0][:256]
                record["login_password"] = form.get("password", [""])[0][:256]
        try:
            with open(LOG_PATH, "a", encoding="utf-8") as fh:
                fh.write(json.dumps(record, ensure_ascii=False) + "\n")
        except OSError as exc:
            print(f"log write failed: {exc}", file=sys.stderr)

    def send(self, status, content_type, payload, body=b"", extra_headers=None):
        data = payload.encode("utf-8") if isinstance(payload, str) else payload
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("X-Powered-By", "PHP/7.4.3")
        for k, v in (extra_headers or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)
        self.write_log(status, len(data), body)

    def html(self, status, title, body_html, body=b""):
        self.send(status, "text/html; charset=utf-8",
                  PAGE.format(title=title, company=COMPANY, body=body_html), body)

    def route(self, body=b""):
        path = urlsplit(self.path).path
        norm = path.rstrip("/") or "/"

        if norm == "/":
            return self.html(200, "Home", HOME, body)
        if norm in FAKE_FILES:
            ctype, content = FAKE_FILES[norm]
            return self.send(200, ctype, content, body)
        if norm in DIR_LISTINGS:
            items = "".join(f'<li><a href="{norm}/{f}">{f}</a></li>' for f in DIR_LISTINGS[norm])
            return self.html(200, f"Index of {norm}", f'<div class="card"><h2>Index of {norm}/</h2><ul>{items}</ul></div>', body)
        if norm == "/api":
            if "json" in self.headers.get("Accept", ""):
                status, obj = api_payload(norm)
                return self.send(status, "application/json", json.dumps(obj), body)
            return self.html(200, "API Documentation", API_DOCS, body)
        if norm.startswith("/api/"):
            if norm == "/api/v1/auth/token":
                return self.send(401, "application/json", json.dumps({"status": "error", "message": "invalid client credentials"}), body)
            status, obj = api_payload(norm)
            return self.send(status, "application/json", json.dumps(obj), body)
        if norm in ("/login", "/admin", "/dashboard", "/wp-login.php", "/phpmyadmin", "/administrator"):
            heading = "Administration" if norm != "/login" else "Customer Portal"
            msg = ""
            if self.command == "POST":
                msg = '<p style="color:#b42318">Invalid username or password.</p>'
            status = 401 if self.command == "POST" else 200
            return self.html(status, heading, LOGIN.format(heading=heading, msg=msg, action=norm), body)
        if norm == "/robots.txt":
            return self.send(200, "text/plain", "User-agent: *\nDisallow: /admin\nDisallow: /backup\nDisallow: /config\n", body)
        if norm == "/config":
            return self.send(302, "text/plain", "", body, {"Location": "/config.json"})
        return self.html(404, "Not Found", '<div class="card"><h2>404 Not Found</h2><p>The requested resource was not found.</p></div>', body)

    def do_GET(self):
        self.route()

    def do_HEAD(self):
        self.route()

    def do_POST(self):
        self.route(self.read_body())

    def do_PUT(self):
        self.route(self.read_body())

    def do_DELETE(self):
        self.route(self.read_body())

    def do_OPTIONS(self):
        self.send(204, "text/plain", "", b"", {"Allow": "GET, POST, HEAD, OPTIONS"})


def main():
    os.makedirs(os.path.dirname(LOG_PATH), exist_ok=True)
    httpd = ThreadingHTTPServer((LISTEN_HOST, LISTEN_PORT), Handler)
    httpd.daemon_threads = True
    print(f"cloudbait-web listening on {LISTEN_HOST}:{LISTEN_PORT}, logging to {LOG_PATH}", flush=True)
    httpd.serve_forever()


if __name__ == "__main__":
    main()
