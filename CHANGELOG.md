# Changelog

## 0.1.1

- Add `--min-grade <A-F>`: exit non-zero if the grade is below a threshold (a public server is N/A and always passes). A cleaner CI gate than `--strict`.
- Add a reusable GitHub Action (`action.yml`) to gate an MCP server's OAuth conformance in CI.
- Add `.github/workflows/scan.yml`: a scheduled weekly re-scan that keeps the published ecosystem dataset current.

## 0.1.0

- Initial release. Read-only, non-destructive CLI that grades any MCP server's OAuth implementation against the MCP authorization spec (RFC 9728 PRM, RFC 8414 AS metadata, OAuth 2.1 PKCE, RFC 8707 audience, token validation).
- `--json`, `--strict`, `--spec <revision>`, `--verbose`.
- Published scan of 31 public MCP servers.
