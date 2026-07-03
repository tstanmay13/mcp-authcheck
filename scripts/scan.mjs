#!/usr/bin/env node
/**
 * Scan a list of public MCP server endpoints and emit both per-server reports
 * and an aggregate summary. This produces the dataset published in the README.
 *
 * Usage:
 *   node scripts/scan.mjs                 # scan the built-in list
 *   node scripts/scan.mjs urls.txt        # scan URLs from a file (one per line)
 *   node scripts/scan.mjs --out data.json # write full JSON results
 *
 * Reads only: every check is non-destructive and sends no credentials.
 */
import { readFileSync, writeFileSync } from "node:fs";
import { audit } from "../dist/index.js";

// Known public remote MCP endpoints (2026). Endpoints move; unreachable ones
// are reported as such rather than silently dropped.
const DEFAULT_TARGETS = [
  "https://mcp.linear.app/mcp",
  "https://mcp.notion.com/mcp",
  "https://mcp.sentry.dev/mcp",
  "https://api.githubcopilot.com/mcp/",
  "https://mcp.stripe.com",
  "https://mcp.asana.com/sse",
  "https://mcp.atlassian.com/v1/sse",
  "https://mcp.intercom.com/mcp",
  "https://mcp.vercel.com",
  "https://mcp.neon.tech/sse",
  "https://mcp.paypal.com/mcp",
  "https://mcp.squareup.com/sse",
  "https://huggingface.co/mcp",
  "https://mcp.context7.com/mcp",
  "https://mcp.deepwiki.com/mcp",
  "https://gitmcp.io/docs",
  "https://mcp.globalping.dev/sse",
  "https://mcp.webflow.com/sse",
  "https://mcp.hubspot.com/anthropic",
  "https://mcp.zapier.com/api/mcp/mcp",
  "https://mcp.canva.com/mcp",
  "https://mcp.cloudflare.com/mcp",
  "https://mcp.close.com/mcp",
  "https://mcp.wix.com/sse",
  "https://mcp.prisma.io/mcp",
  "https://mcp.buildkite.com/mcp",
  "https://mcp.simplescraper.io/mcp",
  "https://mcp.grafana.com/mcp",
  "https://mcp.monday.com/sse",
  "https://mcp.box.com/mcp",
  "https://mcp.stytch.dev/mcp",
];

const args = process.argv.slice(2);
let outFile;
const files = [];
for (let i = 0; i < args.length; i++) {
  if (args[i] === "--out") outFile = args[++i];
  else files.push(args[i]);
}

const rawTargets =
  files.length > 0
    ? files
        .flatMap((f) => readFileSync(f, "utf8").split("\n"))
        .map((s) => s.trim())
        .filter((s) => s && !s.startsWith("#"))
    : DEFAULT_TARGETS;
const targets = [...new Set(rawTargets)];

const reports = [];
for (const target of targets) {
  process.stderr.write(`scanning ${target} ... `);
  try {
    const report = await audit(target, { timeoutMs: 15000 });
    reports.push(report);
    process.stderr.write(`${report.grade.letter} ${report.grade.score}\n`);
  } catch (err) {
    process.stderr.write(`ERROR ${err?.message ?? err}\n`);
    reports.push({ target, error: String(err?.message ?? err) });
  }
}

// --- aggregate ---
const reachable = reports.filter((r) => r.grade);
// Only servers that enforce auth get a letter grade. Bucket the rest so a
// public docs server or an unreachable/404 URL never counts as a failure.
const graded = reachable.filter((r) => r.posture === "protected");
const publicServers = reachable.filter((r) => r.posture === "public");
const undetermined = reachable.filter((r) => r.posture === "unknown");
const dist = { A: 0, B: 0, C: 0, D: 0, F: 0 };
for (const r of graded) dist[r.grade.letter]++;

// Per-check-id pass/fail/warn tally across protected (graded) servers.
const checkTally = {};
for (const r of graded) {
  for (const c of r.results) {
    const id = c.id.replace(/\[.*\]$/, ""); // collapse per-issuer suffixes
    checkTally[id] ??= { pass: 0, fail: 0, warn: 0, skip: 0, error: 0, info: 0, title: c.title };
    checkTally[id][c.status]++;
  }
}

const summary = {
  scannedAt: new Date().toISOString(),
  toolVersion: reachable[0]?.toolVersion,
  specVersion: reachable[0]?.specVersion,
  total: reports.length,
  reachable: reachable.length,
  gradedProtected: graded.length,
  publicNotGraded: publicServers.length,
  undetermined: undetermined.length,
  unreachable: reports.length - reachable.length,
  gradeDistribution: dist,
  medianScore: median(graded.map((r) => r.grade.score).filter((s) => s !== null)),
  publicServers: publicServers.map((r) => r.target),
  undeterminedServers: undetermined.map((r) => r.target),
  checkTally,
};

function median(xs) {
  if (xs.length === 0) return null;
  const s = [...xs].sort((a, b) => a - b);
  const m = Math.floor(s.length / 2);
  return s.length % 2 ? s[m] : Math.round((s[m - 1] + s[m]) / 2);
}

process.stderr.write("\n");
console.log(JSON.stringify(summary, null, 2));

if (outFile) {
  writeFileSync(outFile, JSON.stringify({ summary, reports }, null, 2));
  process.stderr.write(`\nfull results written to ${outFile}\n`);
}
