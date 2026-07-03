import type { CheckResult, CheckStatus, Grade, Posture, Severity } from "./types.js";

/**
 * Weight each severity contributes to the score. A failing `critical` check
 * costs far more than a failing `low` one. `info` checks never affect the score.
 */
const SEVERITY_WEIGHT: Record<Severity, number> = {
  critical: 40,
  high: 20,
  medium: 10,
  low: 4,
  info: 0,
};

/**
 * A failed check of this severity or worse caps the letter grade, no matter
 * how high the numeric score. Rationale: a server that passes 20 cosmetic
 * checks but accepts tokens minted for another audience is not a "B" server —
 * the single critical hole is disqualifying. This mirrors how SSL Labs caps
 * a grade to F on a broken certificate chain regardless of cipher strength.
 */
/** The graded letters (excludes the "N/A" public-server sentinel). */
type Letter = "A" | "B" | "C" | "D" | "F";

const GATE: Partial<Record<Severity, Letter>> = {
  critical: "F",
  high: "C",
};

/**
 * Score = 100 * (earned weight / applicable weight), where a check earns full
 * weight on pass, half on warn, and zero on fail. skip/error/info checks are
 * excluded from the denominator so a server is never penalized for a probe we
 * could not run or a requirement that did not apply.
 */
export function computeGrade(results: CheckResult[], posture: Posture = "protected"): Grade {
  // Only servers that actually enforce authorization get a letter grade. A
  // public server opted out of auth; an "unknown" server could not be reached
  // as an MCP endpoint (e.g. every probe 404'd or the host was unreachable).
  // Grading either would be a misleading failure, so both are N/A.
  if (posture !== "protected") return { score: null, letter: "N/A" };

  let earned = 0;
  let applicable = 0;
  let worstGatedFail: Severity | undefined;

  for (const r of results) {
    const weight = SEVERITY_WEIGHT[r.severity];
    if (weight === 0) continue; // info-severity: never affects score
    if (r.status === "skip" || r.status === "error" || r.status === "info")
      continue;

    applicable += weight;
    if (r.status === "pass") earned += weight;
    else if (r.status === "warn") earned += weight / 2;
    else if (r.status === "fail") {
      if (GATE[r.severity] && isWorse(r.severity, worstGatedFail)) {
        worstGatedFail = r.severity;
      }
    }
  }

  // No weighted checks ran at all (protected posture but every check skipped or
  // errored): nothing to grade, so N/A rather than a false zero.
  if (applicable === 0) return { score: null, letter: "N/A" };

  const score = Math.round((earned / applicable) * 100);
  let letter = letterFor(score);

  // Apply gate caps: a gated failure cannot score better than its cap.
  if (worstGatedFail) {
    const cap = GATE[worstGatedFail]!;
    if (rank(letter) > rank(cap)) letter = cap;
  }

  return { score, letter };
}

function letterFor(score: number): Letter {
  if (score >= 90) return "A";
  if (score >= 80) return "B";
  if (score >= 70) return "C";
  if (score >= 60) return "D";
  return "F";
}

// Higher rank = better grade. Used to compare against a cap.
function rank(letter: Letter): number {
  return { F: 0, D: 1, C: 2, B: 3, A: 4 }[letter];
}

const SEVERITY_ORDER: Severity[] = ["low", "medium", "high", "critical"];
function isWorse(a: Severity, b: Severity | undefined): boolean {
  if (!b) return true;
  return SEVERITY_ORDER.indexOf(a) > SEVERITY_ORDER.indexOf(b);
}

/**
 * Whether a grade meets a minimum letter threshold, for `--min-grade` CI gating.
 * A public server (N/A) is never graded for auth, so it always passes.
 */
export function gradeMeetsMin(letter: Grade["letter"], min: string): boolean {
  if (letter === "N/A") return true;
  const rank: Record<string, number> = { F: 0, D: 1, C: 2, B: 3, A: 4 };
  const got = rank[letter];
  const need = rank[min.toUpperCase()];
  if (got === undefined || need === undefined) return true;
  return got >= need;
}

export function summarize(results: CheckResult[]): Record<CheckStatus, number> {
  const s: Record<CheckStatus, number> = {
    pass: 0,
    fail: 0,
    warn: 0,
    skip: 0,
    error: 0,
    info: 0,
  };
  for (const r of results) s[r.status]++;
  return s;
}
