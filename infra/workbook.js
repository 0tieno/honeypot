// Builds the "WHO IS ATTACKING MY CLOUD?" Azure Workbook body from queries/*.kql.
// Usage: node infra/workbook.js <workspaceResourceId> <location> > body.json
const fs = require("fs");
const path = require("path");

const [workspaceId, location] = process.argv.slice(2);
const dir = path.join(__dirname, "..", "queries");

// Each .kql file = shared header (comment + let statements) + one or more panel queries separated by ";".
function load(file) {
  const text = fs.readFileSync(path.join(dir, file), "utf8");
  const lines = text.split(/\r?\n/);
  const header = [], body = [];
  for (const l of lines) (body.length === 0 && (l.startsWith("let ") || l.startsWith("// Excludes")) ? header : body).push(l);
  const title = body.find(l => l.startsWith("// "))?.replace(/^\/\/\s*/, "") ?? file;
  const queries = body.filter(l => !/^\/\/ \d\d /.test(l)).join("\n")
    .split(/;\s*\n/).map(q => q.trim()).filter(Boolean)
    .map(q => q.replace(/\n\|\s*render \w+\s*$/, ""));
  return { title, header: header.join("\n"), queries };
}

const viz = { "03": "timechart", "04": "barchart", "01": "table" };
const items = [{
  type: 1, name: "title",
  content: { json: "# WHO IS ATTACKING MY CLOUD?\nOperation: Cloud Bait. Live telemetry from a decoy Azure workload (`cb-vm-01`). Your own test traffic is excluded." },
}];

for (const file of fs.readdirSync(dir).filter(f => f.endsWith(".kql")).sort()) {
  const { title, header, queries } = load(file);
  const num = file.slice(0, 2);
  queries.forEach((q, i) => {
    const sub = queries.length > 1 ? (i === 0 ? "" : " (cont.)") : "";
    items.push({
      type: 3, name: `panel-${num}-${i}`,
      customWidth: ["03", "07", "09"].includes(num) ? "100" : "50",
      content: {
        version: "KqlItem/1.0",
        query: `${header}\n${q}`,
        size: 0,
        title: title + sub,
        timeContext: { durationMs: 604800000 },
        queryType: 0,
        resourceType: "microsoft.operationalinsights/workspaces",
        visualization: viz[num] || "table",
        gridSettings: { rowLimit: 50 },
      },
    });
  });
}

const serializedData = JSON.stringify({
  version: "Notebook/1.0", items,
  fallbackResourceIds: [workspaceId],
  $schema: "https://github.com/Microsoft/Application-Insights-Workbooks/blob/master/schema/workbook.json",
});

process.stdout.write(JSON.stringify({
  location, kind: "shared",
  tags: { project: "cloud-bait" },
  properties: { displayName: "Cloud Bait - Who is attacking my cloud?", serializedData, sourceId: workspaceId, category: "workbook" },
}));
