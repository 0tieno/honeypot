#!/usr/bin/env bash
# End-to-end self-test: generate tagged traffic against the honeypot, then confirm it
# landed in Log Analytics. Run from the repo root:  tests/selftest.sh [--no-wait]
# Self-test traffic is tagged (user agent / username "cbselftest-<id>") so KQL can exclude it.
set -uo pipefail
export MSYS_NO_PATHCONV=1
ROOT="$(cd "$(dirname "$0")/.." && pwd)"
IP=${CB_IP:-$(az network public-ip show -g cloud-bait-rg -n cb-public-ip --query ipAddress -o tsv)}
ID=$(date +%s)
TAG="cbselftest-$ID"
pass=0; fail=0
ok()   { echo "  PASS  $*"; pass=$((pass+1)); }
bad()  { echo "  FAIL  $*"; fail=$((fail+1)); }
check() { if [ "$2" = "$3" ]; then ok "$1 ($2)"; else bad "$1 (got $2, want $3)"; fi; }

echo "== Honeypot $IP, tag $TAG"

echo "-- Web (HTTP/HTTPS)"
code() { curl -sk -o /dev/null -m 10 -w '%{http_code}' -A "$TAG" "$@"; }
check "GET  http  /"                  "$(code http://$IP/)" 200
check "GET  http  /.env"              "$(code http://$IP/.env)" 200
check "GET  https /admin"             "$(code https://$IP/admin)" 200
check "GET  http  /api/v1/customers"  "$(code http://$IP/api/v1/customers)" 200
check "GET  http  /backup/backup_2026.sql" "$(code http://$IP/backup/backup_2026.sql)" 200
check "POST http  /login"             "$(code -d "username=$TAG&password=pw-$ID" http://$IP/login)" 401
if curl -s -m 10 -A "$TAG" http://$IP/.env | grep -qiE 'secret|key=|token|password'; then bad ".env contains secret-looking values"; else ok ".env has no secret-looking values"; fi

echo "-- SSH honeypot (port 22 -> Cowrie)"
ASK=$(mktemp); printf '#!/bin/sh\necho pw-%s\n' "$ID" > "$ASK"; chmod +x "$ASK"
OUT=$(echo "echo $TAG-cmd; uname -a; exit" | SSH_ASKPASS="$ASK" SSH_ASKPASS_REQUIRE=force DISPLAY=:0 \
    timeout 40 ssh -tt -p 22 -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null \
    -o PreferredAuthentications=password -o PubkeyAuthentication=no "root@$IP" 2>&1)
rm -f "$ASK"
if echo "$OUT" | grep -q "$TAG-cmd"; then ok "Cowrie accepted login and ran fake shell"; else bad "Cowrie session"; fi
if echo "$OUT" | grep -q "Debian"; then ok "fake uname persona"; else bad "fake uname persona"; fi

echo "-- Telnet honeypot (port 23 -> Cowrie)"
if timeout 8 bash -c "exec 3<>/dev/tcp/$IP/23 && sleep 2" 2>/dev/null; then ok "port 23 accepts connections"; else bad "port 23"; fi

echo "-- Real admin sshd is NOT on 22"
if echo "$OUT" | grep -q "cloudbaitadmin"; then bad "port 22 looks like the real host"; else ok "port 22 is Cowrie, not the real host"; fi

if [ "${1:-}" = "--no-wait" ]; then echo "== $pass passed, $fail failed (Log Analytics check skipped)"; exit $((fail>0)); fi

echo "-- Log Analytics ingestion (polls up to 15 min)"
export CB_WORKSPACE_ID=$(az monitor log-analytics workspace show -g cloud-bait-rg -n cb-law --query customerId -o tsv)
Q="union
 (CloudBaitWeb_CL | where UserAgent == '$TAG' or LoginUsername == '$TAG' | summarize n=count() | extend t='web'),
 (CowrieLogs_CL | where Password == 'pw-$ID' or Command has '$TAG' | summarize n=count() | extend t='cowrie'),
 (Heartbeat | where TimeGenerated > ago(10m) | summarize n=count() | extend t='heartbeat'),
 (Syslog | where TimeGenerated > ago(30m) | summarize n=count() | extend t='syslog')
| project t, n"
for i in $(seq 1 30); do
    R=$("$ROOT/infra/kql.sh" "$Q" 2>/dev/null | tail -n +2)
    web=$(echo "$R" | awk '$1=="web"{print $2}'); cow=$(echo "$R" | awk '$1=="cowrie"{print $2}')
    hb=$(echo "$R" | awk '$1=="heartbeat"{print $2}'); sl=$(echo "$R" | awk '$1=="syslog"{print $2}')
    [ "${web:-0}" -ge 7 ] && [ "${cow:-0}" -ge 2 ] && [ "${hb:-0}" -ge 1 ] && break
    sleep 30
done
[ "${hb:-0}" -ge 1 ]  && ok "Heartbeat in last 10m ($hb)"           || bad "Heartbeat ($hb)"
[ "${sl:-0}" -ge 1 ]  && ok "Syslog in last 30m ($sl)"              || bad "Syslog ($sl)"
[ "${web:-0}" -ge 7 ] && ok "web requests in CloudBaitWeb_CL ($web)" || bad "web requests in CloudBaitWeb_CL (${web:-0})"
[ "${cow:-0}" -ge 2 ] && ok "SSH login + command in CowrieLogs_CL ($cow)" || bad "Cowrie events in CowrieLogs_CL (${cow:-0})"

echo "== $pass passed, $fail failed"
exit $((fail>0))
