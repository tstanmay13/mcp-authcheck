import { audit } from "./engine.js";
import {
  renderText,
  renderJson,
  hasFailures,
  hasSeriousFailures,
} from "./report.js";
import { TOOL_VERSION, SPEC_VERSION, KNOWN_PROTOCOL_VERSIONS } from "./spec.js";

interface Args {
  target?: string;
  json: boolean;
  verbose: boolean;
  strict: boolean;
  timeoutMs?: number;
  protocolVersion?: string;
  help: boolean;
  version: boolean;
}

function parseArgs(argv: string[]): Args {
  const args: Args = {
    json: false,
    verbose: false,
    strict: false,
    help: false,
    version: false,
  };
  for (let i = 0; i < argv.length; i++) {
    const a = argv[i]!;
    switch (a) {
      case "--json":
        args.json = true;
        break;
      case "-v":
      case "--verbose":
        args.verbose = true;
        break;
      case "--strict":
        args.strict = true;
        break;
      case "-h":
      case "--help":
        args.help = true;
        break;
      case "--version":
        args.version = true;
        break;
      case "--timeout":
        args.timeoutMs = Number(argv[++i]) || undefined;
        break;
      case "--protocol-version":
        args.protocolVersion = argv[++i];
        break;
      default:
        if (a.startsWith("-")) {
          process.stderr.write(`unknown flag: ${a}\n`);
          process.exit(2);
        }
        args.target = a;
    }
  }
  return args;
}

const HELP = `mcp-authcheck v${TOOL_VERSION} — grade an MCP server against the MCP authorization spec (${SPEC_VERSION})

USAGE
  mcp-authcheck <url> [options]
  npx mcp-authcheck https://mcp.example.com/mcp

OPTIONS
  --json                 Emit the full report as JSON (for CI / piping)
  -v, --verbose          Show skipped checks, evidence, and spec references
  --strict               Exit non-zero only on critical/high failures
                         (default: exit non-zero on any failure)
  --timeout <ms>         Per-request timeout (default 10000)
  --protocol-version <v> MCP-Protocol-Version header to send
                         (known: ${KNOWN_PROTOCOL_VERSIONS.join(", ")})
  -h, --help             Show this help
  --version              Print version

WHAT IT DOES
  Runs read-only, non-destructive conformance checks: the unauthenticated
  challenge (401 + WWW-Authenticate), Protected Resource Metadata (RFC 9728),
  Authorization Server metadata (RFC 8414 / OIDC), PKCE, HTTPS, bogus-token
  rejection, and Origin validation. It sends no credentials and mutates no
  state. See docs/check-catalog.md for every check and its spec citation.

EXIT CODES
  0  no failures (or, with --strict, no critical/high failures)
  1  at least one failing check (see --strict)
  2  usage error
`;

async function main() {
  const args = parseArgs(process.argv.slice(2));

  if (args.version) {
    process.stdout.write(`${TOOL_VERSION}\n`);
    return 0;
  }
  if (args.help || !args.target) {
    process.stdout.write(HELP);
    return args.target ? 0 : args.help ? 0 : 2;
  }

  let report;
  try {
    report = await audit(args.target, {
      timeoutMs: args.timeoutMs,
      protocolVersion: args.protocolVersion,
    });
  } catch (err) {
    process.stderr.write(
      `error: ${err instanceof Error ? err.message : String(err)}\n`,
    );
    return 2;
  }

  if (args.json) {
    process.stdout.write(renderJson(report) + "\n");
  } else {
    process.stdout.write(renderText(report, { verbose: args.verbose }));
  }

  if (args.strict) return hasSeriousFailures(report) ? 1 : 0;
  return hasFailures(report) ? 1 : 0;
}

main().then(
  (code) => process.exit(code),
  (err) => {
    process.stderr.write(`fatal: ${err?.stack ?? err}\n`);
    process.exit(2);
  },
);
