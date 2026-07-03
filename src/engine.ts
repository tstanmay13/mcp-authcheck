import { gather, type GatherOptions } from "./discovery.js";
import { runChecks, posture } from "./checks.js";
import { computeGrade, summarize } from "./score.js";
import { SPEC_VERSION, TOOL_VERSION } from "./spec.js";
import type { Report } from "./types.js";

export interface AuditOptions extends GatherOptions {
  /** Timestamp to stamp the report with (injected for deterministic tests). */
  now?: () => Date;
}

/**
 * End-to-end audit of one MCP server: gather evidence, run the check catalog,
 * grade, and assemble the report. The single entry point the CLI and library
 * both call.
 */
export async function audit(
  target: string,
  opts: AuditOptions = {},
): Promise<Report> {
  const normalized = normalizeTarget(target);
  const evidence = await gather(normalized, opts);
  const results = runChecks(evidence);
  const serverPosture = posture(evidence);
  const grade = computeGrade(results, serverPosture);
  const now = opts.now ? opts.now() : new Date();
  return {
    target: normalized,
    origin: evidence.origin,
    timestamp: now.toISOString(),
    toolVersion: TOOL_VERSION,
    specVersion: SPEC_VERSION,
    posture: serverPosture,
    results,
    grade,
    summary: summarize(results),
  };
}

/** Add a scheme if the user omitted one; reject obviously invalid input. */
export function normalizeTarget(target: string): string {
  const withScheme = /^https?:\/\//i.test(target) ? target : `https://${target}`;
  // Throws on malformed input — surfaced by the CLI as a usage error.
  const u = new URL(withScheme);
  return u.toString();
}
