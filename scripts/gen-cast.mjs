#!/usr/bin/env node
/**
 * Generate an asciinema v2 cast (docs/demo.cast) from real CLI runs, so the
 * checked-in demo always reflects current behavior. Run after `npm run build`:
 *   node scripts/gen-cast.mjs
 * Play it with: asciinema play docs/demo.cast  (or upload to asciinema.org).
 */
import { execFileSync } from "node:child_process";
import { writeFileSync } from "node:fs";
import { fileURLToPath } from "node:url";
import { dirname, join } from "node:path";

const root = join(dirname(fileURLToPath(import.meta.url)), "..");
const cli = join(root, "dist", "cli.js");

const STEPS = [
  { cmd: "mcp-authcheck https://mcp.linear.app/mcp", args: ["https://mcp.linear.app/mcp"] },
  { cmd: "mcp-authcheck https://mcp.intercom.com/mcp", args: ["https://mcp.intercom.com/mcp"] },
  { cmd: "mcp-authcheck https://mcp.deepwiki.com/mcp", args: ["https://mcp.deepwiki.com/mcp"] },
];

const events = [];
let t = 0;
const emit = (s) => { events.push([Number(t.toFixed(3)), "o", s]); };
const type = (s) => { for (const ch of s) { t += 0.03; emit(ch); } };
const pause = (s) => { t += s; };

emit("\x1b[38;5;244m# grade any MCP server's OAuth against the spec — no credentials\x1b[0m\r\n");
pause(0.4);
for (const step of STEPS) {
  emit("\x1b[32m$\x1b[0m ");
  type(step.cmd);
  emit("\r\n");
  pause(0.3);
  let out = "";
  try {
    out = execFileSync("node", [cli, ...step.args, "--timeout", "20000"], {
      env: { ...process.env, FORCE_COLOR: "1" },
      encoding: "utf8",
    });
  } catch (e) {
    out = (e.stdout ?? "") + (e.stderr ?? "");
  }
  emit(out.replace(/\n/g, "\r\n"));
  pause(1.6);
}
emit("\x1b[32m$\x1b[0m ");
pause(1.0);

const header = {
  version: 2,
  width: 96,
  height: 34,
  title: "mcp-authcheck",
  env: { SHELL: "/bin/zsh", TERM: "xterm-256color" },
};
const cast = [JSON.stringify(header), ...events.map((e) => JSON.stringify(e))].join("\n") + "\n";
writeFileSync(join(root, "docs", "demo.cast"), cast);
process.stderr.write(`wrote docs/demo.cast (${events.length} events, ${t.toFixed(1)}s)\n`);
