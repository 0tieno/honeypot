#!/usr/bin/env bash
# Run a KQL query against cb-law.
# Usage: infra/kql.sh 'Heartbeat | take 5'    or    infra/kql.sh -f queries/01_total_activity.kql
set -euo pipefail
if [ "${1:-}" = "-f" ]; then Q=$(cat "$2"); else Q="$1"; fi
WS=${CB_WORKSPACE_ID:-$(az monitor log-analytics workspace show -g cloud-bait-rg -n cb-law --query customerId -o tsv)}
TMP=$(mktemp -d)
trap 'rm -rf "$TMP"' EXIT
node -e 'require("fs").writeFileSync(process.argv[1], JSON.stringify({query: process.argv[2]}))' \
    "$(cygpath -m "$TMP/body.json" 2>/dev/null || echo "$TMP/body.json")" "$Q"
az rest --method post --url "https://api.loganalytics.io/v1/workspaces/$WS/query" \
    --resource https://api.loganalytics.io \
    --body @"$(cygpath -m "$TMP/body.json" 2>/dev/null || echo "$TMP/body.json")" -o json > "$TMP/out.json"
node -e '
const t = JSON.parse(require("fs").readFileSync(process.argv[1], "utf8")).tables[0];
const rows = [t.columns.map(c => c.name), ...t.rows.map(r => r.map(v => v === null ? "" : String(v)))];
const w = rows[0].map((_, i) => Math.min(60, Math.max(...rows.map(r => r[i].length))));
for (const r of rows) console.log(r.map((v, i) => v.slice(0, 60).padEnd(w[i])).join("  "));
' "$(cygpath -m "$TMP/out.json" 2>/dev/null || echo "$TMP/out.json")"
