# mcp-authcheck — Conformance Check Catalog

> The checks this tool runs, each mapped to the exact MCP authorization spec
> clause or RFC section it enforces. Baseline: MCP **2026-07-28** authorization
> spec (OAuth 2.1), with `2025-11-25` and `2025-06-18` as prior stable
> revisions. Every check in Groups A, B, C, E and check D1 is fully
> HTTP-observable, read-only, and non-destructive — it uses no credentials and
> mutates no state. D2/D4 and F2 require fixtures or create state and are gated
> behind an explicit opt-in flag.

## Spec basis (constants baked into the tool)

- **Transport:** Streamable HTTP; a single MCP endpoint accepting `POST`
  ([spec](https://modelcontextprotocol.io/specification/draft/basic/transports/streamable-http)).
- **Auth is optional for MCP**, but once HTTP-transport auth is supported the
  MUSTs below apply ([spec](https://modelcontextprotocol.io/specification/draft/basic/authorization)).
- Built on **OAuth 2.1**, **RFC 8414**, **RFC 7591**, **RFC 8707**, **RFC 9728**,
  **RFC 9207**, and OAuth Client ID Metadata Documents (CIMD). New in the
  2026-07-28 draft vs 2025-06-18: RFC 9207 `iss` validation, CIMD preferred over
  DCR (DCR deprecated), OIDC Discovery accepted alongside RFC 8414.

---

## Group A — Unauthenticated challenge

| ID | Check | Probe | Compliant response | Severity | Reference |
|----|-------|-------|--------------------|----------|-----------|
| A1 | Returns 401 on unauthenticated request | `POST {mcp}` JSON-RPC `initialize`, no `Authorization` | `401` | critical | [authorization §Token Handling](https://modelcontextprotocol.io/specification/draft/basic/authorization) |
| A2 | 401 carries `WWW-Authenticate` with `resource_metadata` | read header from A1 | `Bearer resource_metadata="…/.well-known/oauth-protected-resource"` | critical | [RFC 9728 §5.1](https://datatracker.ietf.org/doc/html/rfc9728#name-www-authenticate-response) |
| A3 | `WWW-Authenticate` includes `scope` (optional) | read header | `scope="…"` present | info | RFC 6750 §3 |

## Group B — Protected Resource Metadata (RFC 9728)

| ID | Check | Probe | Compliant response | Severity | Reference |
|----|-------|-------|--------------------|----------|-----------|
| B1 | PRM endpoint served | `resource_metadata` URL, else well-known (`/.well-known/oauth-protected-resource` with host-insertion for pathful resources) | `200` `application/json` | critical | [RFC 9728 §3](https://datatracker.ietf.org/doc/html/rfc9728) |
| B2 | PRM `resource` present + canonical | parse PRM | `resource` = canonical MCP URI (scheme+host, no fragment) | high | RFC 9728 |
| B3 | PRM `authorization_servers` ≥ 1 | parse PRM | non-empty array of issuer URLs | critical | [authorization-server-discovery](https://modelcontextprotocol.io/specification/draft/basic/authorization/authorization-server-discovery) |
| B4 | PRM recommended fields present | parse PRM | `scopes_supported`, `bearer_methods_supported`, `resource_name`, … | info | RFC 9728 §2 |

## Group C — Authorization Server Metadata (RFC 8414 / OIDC), per issuer

| ID | Check | Compliant response | Severity | Reference |
|----|-------|--------------------|----------|-----------|
| C1 | AS metadata discoverable via mandated fallback order | one of the 2–3 well-known URLs → `200` `application/json` | critical | [authorization-server-discovery](https://modelcontextprotocol.io/specification/draft/basic/authorization/authorization-server-discovery) |
| C2 | AS `issuer` exactly matches | `issuer` == issuer used to build URL | high | RFC 8414 §3.3 |
| C3 | AS required fields present | `issuer`, `response_types_supported`; `authorization_endpoint`, `token_endpoint` | high | [RFC 8414 §2](https://datatracker.ietf.org/doc/html/rfc8414) |
| C4 | PKCE `S256` advertised | `code_challenge_methods_supported` contains `S256` | high | OAuth 2.1 §7.5.2 |
| C5 | All AS endpoints HTTPS | every endpoint URL is `https://` | high | authorization §Communication Security |
| C6 | Registration capability advertised | `client_id_metadata_document_supported: true` and/or `registration_endpoint` | info | [client-registration](https://modelcontextprotocol.io/specification/draft/basic/authorization/client-registration) |
| C7 | RFC 9207 issuer-response support | `authorization_response_iss_parameter_supported: true` | low | [RFC 9207 §2.3](https://datatracker.ietf.org/doc/html/rfc9207) |

## Group D — Token rejection behavior

| ID | Check | Probe | Compliant response | Severity | Observable? |
|----|-------|-------|--------------------|----------|-------------|
| D1 | Rejects a bogus bearer token | `POST {mcp}` `Authorization: Bearer <garbage>` | `401`, ideally `error="invalid_token"` | critical | ✅ read-only |
| D2 | Rejects wrong-audience token | needs a token minted for another resource | `401` | critical | ⚠ needs fixture (opt-in) |
| D3 | No token passthrough to upstream | code/behavior audit | — | critical | ❌ not HTTP-observable (documented, manual) |
| D4 | Insufficient scope → 403 | needs valid token missing a scope | `403` `error="insufficient_scope"` | medium | ⚠ needs fixture (opt-in) |

## Group E — Transport / DNS-rebinding hardening

| ID | Check | Probe | Compliant response | Severity | Reference |
|----|-------|-------|--------------------|----------|-----------|
| E1 | Origin validation | `POST {mcp}` `Origin: https://evil.example` | `403` | high | [streamable-http](https://modelcontextprotocol.io/specification/draft/basic/transports/streamable-http) |
| E2 | Legacy method rejection (2026-07-28) | `GET`/`DELETE {mcp}` | `405` (version-gated) | low | streamable-http §Earlier Revisions |
| E3 | `MCP-Protocol-Version` handling | POST without header | `400` for strict-2026 servers | info | streamable-http §Protocol Version Header |

## Known failure modes encoded above

Token passthrough; missing audience validation (`aud` ignored); resource-URI
mismatch (trailing slash, `http` vs `https`, host case); token reuse across
servers; permissive audience fallback; missing PRM endpoint; no PKCE; missing
RFC 9207 `iss` validation (mix-up attack). Sources:
[WorkOS – MCP resource indicators](https://workos.com/blog/mcp-resource-indicators),
[Aaron Parecki – Let's fix OAuth in MCP](https://aaronparecki.com/2025/04/03/15/oauth-for-model-context-protocol),
[Den Delimarsky – Don't write your own MCP auth](https://den.dev/blog/mcp-prm-auth/).
