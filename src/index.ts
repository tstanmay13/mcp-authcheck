/**
 * Library entry point. Use programmatically:
 *
 *   import { audit, renderJson } from "mcp-authcheck";
 *   const report = await audit("https://mcp.example.com/mcp");
 *   console.log(renderJson(report));
 */
export { audit, normalizeTarget } from "./engine.js";
export type { AuditOptions } from "./engine.js";
export { runChecks, CHECKS } from "./checks.js";
export { computeGrade, summarize } from "./score.js";
export { renderText, renderJson, hasFailures, hasSeriousFailures } from "./report.js";
export { gather } from "./discovery.js";
export { SPEC_VERSION, TOOL_VERSION } from "./spec.js";
export type * from "./types.js";
