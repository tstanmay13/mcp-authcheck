# Public MCP ecosystem scan — 2026-07-03

Produced by `node scripts/scan.mjs` with mcp-authcheck v0.1.0 against the MCP authorization spec 2026-07-28. Every check is read-only and non-destructive.

- **20** servers probed, **20** reachable
- **18** enforce authorization (graded); **2** are public (no auth, graded N/A)
- Grade distribution (protected servers): {"A":14,"B":0,"C":2,"D":0,"F":2}
- Median score (protected servers): **99/100**
- Public servers: https://mcp.deepwiki.com/mcp, https://gitmcp.io/docs

Full per-server results and evidence: `scan-2026-07-03.json`.

## Per-check pass rate (across 18 protected servers)

| Check | Title | pass | fail | warn | skip |
|-------|-------|:----:|:----:|:----:|:----:|
| A1 | Rejects unauthenticated requests with 401 | 18 | 0 | 0 | 0 |
| A2 | 401 challenge advertises resource_metadata (RFC 9728 §5.1) | 15 | 3 | 0 | 0 |
| A3 | WWW-Authenticate advertises scope (optional) | 0 | 0 | 0 | 0 |
| B1 | Protected Resource Metadata endpoint served | 16 | 2 | 0 | 0 |
| B2 | PRM resource field present and canonical | 15 | 0 | 1 | 2 |
| B3 | PRM authorization_servers non-empty | 16 | 0 | 0 | 2 |
| B4 | PRM recommended fields present | 15 | 0 | 0 | 2 |
| C1 | AS metadata discoverable via mandated fallback order | 16 | 0 | 0 | 2 |
| C2 | AS metadata issuer exactly matches | 15 | 1 | 0 | 0 |
| C3 | AS metadata required fields present | 16 | 0 | 0 | 0 |
| C4 | PKCE S256 advertised | 16 | 0 | 0 | 0 |
| C5 | All AS endpoints served over HTTPS | 16 | 0 | 0 | 0 |
| C6 | Client registration capability advertised | 14 | 0 | 0 | 0 |
| C7 | RFC 9207 issuer-response parameter supported | 0 | 0 | 16 | 0 |
| D1 | Validates access tokens (rejects a bogus token) | 13 | 0 | 5 | 0 |
| E1 | Validates Origin header (DNS-rebinding defense) | 16 | 0 | 2 | 0 |
| E2 | Rejects GET on the MCP endpoint (2026-07-28) | 2 | 0 | 0 | 0 |
