# Public MCP ecosystem scan — 2026-10-19

Produced by `node scripts/scan.mjs` with mcp-authcheck v0.1.1 against the MCP authorization spec 2026-07-28. Every check is read-only and non-destructive. This file is regenerated on a schedule by `.github/workflows/scan.yml`.

- **31** servers probed, **31** reachable
- **29** enforce authorization (graded); **2** public (no auth, N/A); **0** could not be resolved as an MCP endpoint (N/A)
- Grade distribution (auth-enforcing servers): A 25 · B 0 · C 2 · D 0 · F 2
- Median score (auth-enforcing servers): **99/100**

Full per-server results and evidence: `latest-scan.json`.

## Per-check pass rate (across 29 auth-enforcing servers)

| Check | Title | pass | fail | warn | skip |
|-------|-------|:----:|:----:|:----:|:----:|
| A1 | Rejects unauthenticated requests with 401 | 29 | 0 | 0 | 0 |
| A2 | 401 challenge advertises resource_metadata (RFC 9728 §5.1) | 26 | 3 | 0 | 0 |
| A3 | WWW-Authenticate advertises scope (optional) | 6 | 0 | 0 | 0 |
| B1 | Protected Resource Metadata endpoint served | 28 | 1 | 0 | 0 |
| B2 | PRM resource field present and canonical | 27 | 0 | 1 | 1 |
| B3 | PRM authorization_servers non-empty | 28 | 0 | 0 | 1 |
| B4 | PRM recommended fields present | 28 | 0 | 0 | 1 |
| C1 | AS metadata discoverable via mandated fallback order | 29 | 0 | 0 | 1 |
| C2 | AS metadata issuer exactly matches | 28 | 1 | 0 | 0 |
| C3 | AS metadata required fields present | 29 | 0 | 0 | 0 |
| C4 | PKCE S256 advertised | 29 | 0 | 0 | 0 |
| C5 | All AS endpoints served over HTTPS | 29 | 0 | 0 | 0 |
| C6 | Client registration capability advertised | 26 | 0 | 0 | 0 |
| C7 | RFC 9207 issuer-response parameter supported | 11 | 0 | 18 | 0 |
| D1 | Validates access tokens (rejects a bogus token) | 25 | 0 | 4 | 0 |
| E1 | Validates Origin header (DNS-rebinding defense) | 29 | 0 | 0 | 0 |
| E2 | Rejects GET on the MCP endpoint (2026-07-28) | 1 | 0 | 0 | 0 |
