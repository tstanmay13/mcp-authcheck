# mcp-authcheck

[![CI](https://github.com/tstanmay13/mcp-authcheck/actions/workflows/ci.yml/badge.svg)](https://github.com/tstanmay13/mcp-authcheck/actions/workflows/ci.yml)
[![npm](https://img.shields.io/npm/v/mcp-authcheck)](https://www.npmjs.com/package/mcp-authcheck)
[![license](https://img.shields.io/badge/license-MIT-blue)](LICENSE)

**Grade any MCP server's OAuth implementation against the MCP authorization spec — in one command, without credentials.**

MCP's authorization spec makes a server a full OAuth 2.1 resource server: it must challenge unauthenticated calls, serve Protected Resource Metadata (RFC 9728), point clients at an authorization server (RFC 8414), enforce PKCE, and validate token audience (RFC 8707). Most of that is invisible until a client breaks against it. `mcp-authcheck` probes a live server the way a spec-compliant client would and reports, check by check, where it conforms and where it doesn't.

```bash
npx mcp-authcheck https://mcp.example.com/mcp
```

No install, no config, no credentials. Every check is read-only and non-destructive.

## Example

```
$ npx mcp-authcheck https://mcp.intercom.com/mcp

mcp-authcheck v0.1.0 · spec 2026-07-28
target  https://mcp.intercom.com/mcp

    F    37/100  capped by critical failure: A2

  ✔ A1        CRITICAL Rejects unauthenticated requests with 401
      server challenges unauthenticated requests (via initialize)
  ✘ A2        CRITICAL 401 challenge advertises resource_metadata (RFC 9728 §5.1)
      a Bearer challenge is present but omits resource_metadata, and no PRM is served — clients cannot discover authorization
      fix: Add resource_metadata="<PRM URL>" to the 401 Bearer challenge.
  ✘ B1        CRITICAL Protected Resource Metadata endpoint served
      no Protected Resource Metadata document found at the advertised or well-known URL
      fix: Serve RFC 9728 metadata (200 application/json) at /.well-known/oauth-protected-resource.
  ▲ D1        MEDIUM   Validates access tokens (rejects a bogus token)
      invalid token rejected via a JSON-RPC error inside HTTP 400 — safe, but the spec requires an HTTP 401
  ...
  2 pass · 2 fail · 1 warn · 4 skip · 0 error
```

`--json` emits the full machine-readable report; `--strict` exits non-zero only on critical/high failures (drop it into CI to gate a release).

## What it found across the public MCP ecosystem

Scanning 31 well-known public MCP servers (2026-07-02, `scripts/scan.mjs`): of the **29 that enforce authorization, 20 scored A, 6 C, and 3 F** (median 99/100). The remaining two aren't graded — one is a public docs server (no auth), one couldn't be resolved as an MCP endpoint. **Roughly a third of auth-enforcing servers have at least one conformance gap**, and three serve broken or absent discovery metadata — meaning a spec-following client cannot locate their authorization server without hard-coding it.

| Server | Grade | Score | Notes |
|--------|:-----:|:-----:|-------|
| huggingface.co | A | 99 | clean |
| mcp.asana.com | A | 99 | clean |
| mcp.buildkite.com | A | 99 | clean |
| mcp.canva.com | A | 99 | clean |
| mcp.grafana.com | A | 99 | clean |
| mcp.hubspot.com | A | 99 | clean |
| mcp.linear.app | A | 99 | clean |
| mcp.monday.com | A | 99 | clean |
| mcp.neon.tech | A | 99 | clean |
| mcp.notion.com | A | 99 | clean |
| mcp.sentry.dev | A | 99 | clean |
| mcp.squareup.com | A | 99 | clean |
| mcp.stripe.com | A | 99 | clean |
| mcp.stytch.dev | A | 99 | clean |
| mcp.webflow.com | A | 99 | clean |
| api.githubcopilot.com | A | 98 | clean |
| mcp.cloudflare.com | A | 98 | clean |
| mcp.paypal.com | A | 98 | clean |
| mcp.context7.com | A | 97 | clean |
| mcp.globalping.dev | A | 97 | clean |
| mcp.box.com | C | 94 | AS metadata `issuer` (`https://api.box.com`) ≠ advertised issuer — RFC 8414 §3.3 |
| mcp.close.com | C | 94 | AS metadata `issuer` (`https://api.close.com`) ≠ advertised issuer — RFC 8414 §3.3 |
| mcp.vercel.com | C | 94 | AS metadata `issuer` (`https://vercel.com`) ≠ advertised issuer (`https://mcp.vercel.com`) — RFC 8414 §3.3 |
| mcp.wix.com | C | 93 | 401 challenge omits `resource_metadata` (PRM reachable at well-known path) |
| mcp.zapier.com | C | 93 | 401 challenge omits `resource_metadata` (PRM reachable at well-known path) |
| mcp.prisma.io | C | 87 | 401 challenge omits `resource_metadata`; AS metadata issuer mismatch (RFC 8414 §3.3) |
| mcp.simplescraper.io | F | 61 | PRM served but malformed — missing `resource`; `authorization_servers` holds objects, not issuer strings (RFC 9728) |
| mcp.atlassian.com | F | 37 | challenges for OAuth but serves no Protected Resource Metadata (RFC 9728) |
| mcp.intercom.com | F | 37 | challenges for OAuth but serves no Protected Resource Metadata (RFC 9728) |

Not graded: `mcp.deepwiki.com` (public — no auth enforced), `gitmcp.io` (could not be resolved as an MCP endpoint). Every non-A finding above was reproduced by hand against the live server. Reproduce the whole scan with `npm run build && node scripts/scan.mjs`. Full JSON in [`data/scan-2026-07-02.json`](data/scan-2026-07-02.json).

## What it checks

Grouped by probe, each mapped to the exact spec clause or RFC section it enforces. Full catalog with severities and citations: [`docs/check-catalog.md`](docs/check-catalog.md).

- **Unauthenticated challenge** — 401 on an unauthenticated request; `WWW-Authenticate: Bearer` carrying `resource_metadata` (RFC 9728 §5.1).
- **Protected Resource Metadata** (RFC 9728) — the document is served; `resource` is the canonical server URI; `authorization_servers` names at least one issuer.
- **Authorization Server metadata** (RFC 8414 / OIDC) — discoverable via the spec's mandated well-known fallback order; `issuer` matches (mix-up defense); required fields present; **PKCE `S256`** advertised; all endpoints HTTPS.
- **Token validation** — a bogus token against the read-only `tools/list` operation is rejected, distinguishing a true rejection from a server that returns protected data to an invalid token.
- **Transport hardening** — Origin validation and legacy-method rejection (scored low; version-aware).

Grade is a weighted score with **gate caps**: a failing critical check (e.g. no token validation) caps the grade at F regardless of the numeric score, the way SSL Labs caps a broken chain — because one hole that lets a bad token through is disqualifying no matter how many cosmetic checks pass.

## How it works

The design is deliberately boring where it counts: **gather all evidence once, then grade with pure functions.** [`discovery.ts`](src/discovery.ts) performs every network exchange up front — the unauthenticated challenge, a bogus-token `tools/list`, PRM discovery, and per-issuer AS-metadata resolution following RFC 8414's well-known path-insertion rules. Each [check](src/checks.ts) is a pure function over that evidence, which is why the whole catalog is unit-tested against fixtures with no network (`src/checks.test.ts`). Bodies are parsed whether they arrive as JSON or MCP's `text/event-stream`, so an auth rejection carried inside an HTTP 200 JSON-RPC error is graded as a rejection, not a bypass.

Two calibration decisions keep the grades honest:

- **Public servers are graded N/A, not F.** A docs server that requires no auth hasn't failed an auth spec — it opted out. The tool detects auth posture from whether a protected operation is actually challenged, and only grades servers that enforce authorization.
- **Wrong-but-safe is not catastrophic.** A server that rejects a bad token with `400` instead of `401` is a spec deviation (medium), not an authentication bypass (critical). Only a server that *accepts* an invalid token fails critically.

The gating requirements (PRM, AS discovery, PKCE, token validation) come from RFC 9728/8414 and OAuth 2.1, stable in MCP since the 2025-06-18 revision. The 2026-07-28 additions (RFC 9207 `iss`, CIMD) are scored informationally so they never cap a grade before the spec is final.

## Non-destructive guarantee

`mcp-authcheck` never sends a credential it wasn't given and never mutates state. It reads discovery documents, sends one deliberately-invalid token to a read-only operation, and inspects challenge responses. It does not attempt Dynamic Client Registration (which creates state), call any tool, or exercise any write path.

## Programmatic use

```ts
import { audit, renderJson } from "mcp-authcheck";

const report = await audit("https://mcp.example.com/mcp");
console.log(report.grade); // { score: 99, letter: "A" }
console.log(renderJson(report));
```

## Development

```bash
npm install
npm test          # 36 tests, no network
npm run build
node dist/cli.js https://mcp.example.com/mcp
```

## License

MIT
