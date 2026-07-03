import type { CheckResult, CheckStatus, Report, Severity } from "./types.js";

/**
 * Terminal and JSON renderers for a Report. Colors auto-disable when stdout is
 * not a TTY or NO_COLOR is set, so piped/CI output stays clean.
 */

const useColor =
  !process.env.NO_COLOR &&
  process.env.TERM !== "dumb" &&
  (!!process.env.FORCE_COLOR || process.stdout.isTTY);

const c = {
  reset: paint("\x1b[0m"),
  bold: paint("\x1b[1m"),
  dim: paint("\x1b[2m"),
  green: paint("\x1b[32m"),
  red: paint("\x1b[31m"),
  yellow: paint("\x1b[33m"),
  blue: paint("\x1b[34m"),
  gray: paint("\x1b[90m"),
  cyan: paint("\x1b[36m"),
};

function paint(code: string) {
  return (s: string) => (useColor ? `${code}${s}\x1b[0m` : s);
}

const STATUS_GLYPH: Record<CheckStatus, string> = {
  pass: "✔",
  fail: "✘",
  warn: "▲",
  skip: "•",
  error: "!",
  info: "ℹ",
};

function statusColor(s: CheckStatus): (t: string) => string {
  switch (s) {
    case "pass":
      return c.green;
    case "fail":
      return c.red;
    case "warn":
      return c.yellow;
    case "error":
      return c.red;
    case "skip":
      return c.gray;
    case "info":
      return c.blue;
  }
}

function gradeColor(letter: string): (t: string) => string {
  if (letter === "A" || letter === "B") return c.green;
  if (letter === "C") return c.yellow;
  if (letter === "N/A") return c.blue;
  return c.red;
}

const SEVERITY_ORDER: Severity[] = ["critical", "high", "medium", "low", "info"];

export function renderText(report: Report, opts: { verbose?: boolean } = {}): string {
  const lines: string[] = [];
  lines.push("");
  lines.push(`${c.bold("mcp-authcheck")} ${c.dim(`v${report.toolVersion} · spec ${report.specVersion}`)}`);
  lines.push(`${c.dim("target")}  ${report.target}`);
  lines.push("");

  // Grade banner
  const g = gradeColor(report.grade.letter);
  const scoreText =
    report.grade.score === null ? "" : `${c.bold(`${report.grade.score}/100`)}  `;
  lines.push(
    `  ${g(c.bold(`  ${report.grade.letter}  `))}  ${scoreText}${gradeSubtitle(report)}`,
  );
  lines.push("");

  // Sort by severity then id so the most important results read first.
  const sorted = [...report.results].sort(
    (a, b) =>
      SEVERITY_ORDER.indexOf(a.severity) - SEVERITY_ORDER.indexOf(b.severity) ||
      a.id.localeCompare(b.id),
  );

  for (const r of sorted) {
    if (!opts.verbose && r.status === "skip") continue;
    const glyph = statusColor(r.status)(STATUS_GLYPH[r.status]);
    const id = c.dim(r.id.padEnd(9));
    const sev = severityTag(r.severity);
    lines.push(`  ${glyph} ${id} ${sev} ${r.title}`);
    lines.push(`      ${c.dim(r.message)}`);
    if (r.status !== "pass" && r.status !== "skip" && r.remediation) {
      lines.push(`      ${c.cyan("fix:")} ${r.remediation}`);
    }
    if (opts.verbose && r.evidence && Object.keys(r.evidence).length > 0) {
      lines.push(`      ${c.gray(JSON.stringify(r.evidence))}`);
    }
    if (opts.verbose) {
      lines.push(`      ${c.gray(`${r.requirement} · ${r.reference.spec} · ${r.reference.url}`)}`);
    }
  }

  lines.push("");
  lines.push(`  ${summaryLine(report)}`);
  lines.push("");
  return lines.join("\n");
}

function gradeSubtitle(report: Report): string {
  if (report.posture === "public") {
    return c.blue("public server — no authorization enforced; auth conformance not applicable");
  }
  if (report.posture === "unknown") {
    return c.yellow(
      "could not determine auth posture — the endpoint may not be an MCP server at this URL (unreachable or 404)",
    );
  }
  const failed = report.results.filter((r) => r.status === "fail");
  const worstCrit = failed.find((r) => r.severity === "critical");
  if (worstCrit) return c.red(`capped by critical failure: ${worstCrit.id}`);
  const worstHigh = failed.find((r) => r.severity === "high");
  if (worstHigh) return c.yellow(`capped by high-severity failure: ${worstHigh.id}`);
  if (failed.length === 0) return c.green("no failures");
  return c.dim(`${failed.length} failure(s)`);
}

function severityTag(s: Severity): string {
  const label = s.toUpperCase().padEnd(8);
  switch (s) {
    case "critical":
      return c.red(label);
    case "high":
      return c.yellow(label);
    case "medium":
      return c.blue(label);
    case "low":
      return c.gray(label);
    case "info":
      return c.gray(label);
  }
}

function summaryLine(report: Report): string {
  const s = report.summary;
  const parts = [
    c.green(`${s.pass} pass`),
    s.fail ? c.red(`${s.fail} fail`) : c.dim(`${s.fail} fail`),
    s.warn ? c.yellow(`${s.warn} warn`) : c.dim(`${s.warn} warn`),
    c.gray(`${s.skip} skip`),
    s.error ? c.red(`${s.error} error`) : c.dim(`${s.error} error`),
  ];
  return parts.join(c.dim(" · "));
}

export function renderJson(report: Report): string {
  return JSON.stringify(report, null, 2);
}

/** True if the report contains any failing check (drives CLI exit code). */
export function hasFailures(report: Report): boolean {
  return report.results.some((r) => r.status === "fail");
}

/** True if any critical/high check failed (drives --strict exit). */
export function hasSeriousFailures(report: Report): boolean {
  return report.results.some(
    (r: CheckResult) =>
      r.status === "fail" && (r.severity === "critical" || r.severity === "high"),
  );
}
