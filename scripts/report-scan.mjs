#!/usr/bin/env node
/**
 * Regenerate data/README.md (the human-readable ecosystem summary) from a scan
 * JSON file produced by scripts/scan.mjs. Kept as a committed script so CI can
 * refresh the published dataset on a schedule.
 *
 * Usage: node scripts/report-scan.mjs [data/latest-scan.json]
 */
import { readFileSync, writeFileSync } from "node:fs";

const inPath = process.argv[2] ?? "data/latest-scan.json";
const { summary: s } = JSON.parse(readFileSync(inPath, "utf8"));

const tally = Object.entries(s.checkTally)
  .sort((a, b) => a[0].localeCompare(b[0]))
  .map(([id, t]) => `| ${id} | ${t.title} | ${t.pass} | ${t.fail} | ${t.warn} | ${t.skip} |`)
  .join("\n");

const out = `# Public MCP ecosystem scan — ${s.scannedAt.slice(0, 10)}

Produced by \`node scripts/scan.mjs\` with mcp-authcheck v${s.toolVersion} against the MCP authorization spec ${s.specVersion}. Every check is read-only and non-destructive. This file is regenerated on a schedule by \`.github/workflows/scan.yml\`.

- **${s.total}** servers probed, **${s.reachable}** reachable
- **${s.gradedProtected}** enforce authorization (graded); **${s.publicNotGraded}** public (no auth, N/A); **${s.undetermined}** could not be resolved as an MCP endpoint (N/A)
- Grade distribution (auth-enforcing servers): A ${s.gradeDistribution.A} · B ${s.gradeDistribution.B} · C ${s.gradeDistribution.C} · D ${s.gradeDistribution.D} · F ${s.gradeDistribution.F}
- Median score (auth-enforcing servers): **${s.medianScore}/100**

Full per-server results and evidence: \`${inPath.split("/").pop()}\`.

## Per-check pass rate (across ${s.gradedProtected} auth-enforcing servers)

| Check | Title | pass | fail | warn | skip |
|-------|-------|:----:|:----:|:----:|:----:|
${tally}
`;

writeFileSync("data/README.md", out);
process.stderr.write("wrote data/README.md\n");
