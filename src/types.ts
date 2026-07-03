/**
 * Core types for the conformance engine.
 *
 * A run probes one MCP server URL, executes a catalog of independent checks
 * against evidence gathered up front, and produces a graded report. Every
 * check is read-only: it inspects discovery documents and unauthenticated
 * responses. It never sends a token it was not given and never mutates state.
 */

export type Severity = "critical" | "high" | "medium" | "low" | "info";

export type CheckStatus =
  | "pass"
  | "fail"
  | "warn"
  /** The check could not run because a prerequisite was absent (e.g. no PRM doc). */
  | "skip"
  /** The probe itself errored (network, timeout) — not the server's fault to grade. */
  | "error"
  /** Observed, no pass/fail judgment — used only by info-severity checks. */
  | "info";

/** RFC-2119-style requirement level the check enforces. */
export type RequirementLevel = "MUST" | "SHOULD" | "MAY";

export interface CheckResult {
  id: string;
  title: string;
  status: CheckStatus;
  severity: Severity;
  requirement: RequirementLevel;
  /** One-line human summary of the outcome. */
  message: string;
  /** The spec/RFC clause this maps to, for the report. */
  reference: { spec: string; section?: string; url: string };
  /** Concrete evidence (headers seen, fields present/absent) for the -v report. */
  evidence?: Record<string, unknown>;
  /** Actionable fix, shown when the check does not pass. */
  remediation?: string;
}

/**
 * A single HTTP exchange captured during evidence gathering, retained so
 * checks can reason over the same observations and the report can show them.
 */
export interface Probe {
  label: string;
  request: { method: string; url: string; headers: Record<string, string> };
  response?: {
    status: number;
    headers: Record<string, string>;
    /** Parsed JSON body when the response was JSON; raw text otherwise. */
    json?: unknown;
    text?: string;
  };
  error?: string;
  /** Wall-clock milliseconds for the exchange. */
  durationMs: number;
}

/**
 * Everything gathered about a target before checks run. Checks are pure
 * functions over this object, which makes them trivially unit-testable.
 */
export interface Evidence {
  /** The MCP endpoint URL as given by the user (normalized). */
  target: string;
  /** Origin used for well-known discovery, e.g. https://host[:port]. */
  origin: string;
  /** MCP spec revision the checks grade against (drives version-specific rules). */
  specVersion: string;
  probes: Probe[];
  /** RFC 9728 Protected Resource Metadata, if discovered and parsed. */
  protectedResourceMetadata?: {
    url: string;
    doc: Record<string, unknown>;
  };
  /** RFC 8414 Authorization Server Metadata for each discovered AS. */
  authServerMetadata: Array<{
    issuer: string;
    url: string;
    doc: Record<string, unknown>;
  }>;
  /** Parsed WWW-Authenticate header challenges from the unauthenticated probe. */
  wwwAuthenticate?: WwwAuthenticateChallenge[];
}

export interface WwwAuthenticateChallenge {
  scheme: string;
  params: Record<string, string>;
}

/** A check is a pure function from gathered evidence to a result. */
export type Check = (evidence: Evidence) => CheckResult | CheckResult[];

/** Whether the server enforces authorization, which decides if it is gradeable. */
export type Posture = "protected" | "public" | "unknown";

export interface Grade {
  /** 0-100. Null when auth conformance does not apply (a public server). */
  score: number | null;
  /**
   * A–F letter derived from the score with gate caps applied, or "N/A" when the
   * server is public and the auth-conformance checks do not apply to it.
   */
  letter: "A" | "B" | "C" | "D" | "F" | "N/A";
}

export interface Report {
  target: string;
  origin: string;
  timestamp: string;
  toolVersion: string;
  specVersion: string;
  /** Whether the server enforces auth (decides whether the grade applies). */
  posture: Posture;
  results: CheckResult[];
  grade: Grade;
  /** Counts by status for the summary line. */
  summary: Record<CheckStatus, number>;
}
