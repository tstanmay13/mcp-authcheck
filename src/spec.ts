/**
 * Spec constants and well-known URL construction, implemented literally from
 * RFC 9728 §3.1 and RFC 8414 §3.1 (the "insert the well-known suffix after the
 * host, before the resource path" rule) and the MCP authorization spec's
 * mandated discovery fallback order.
 */

export const TOOL_VERSION = "0.1.0";
export const SPEC_VERSION = "2026-07-28";

/** MCP protocol versions this tool knows about, newest first. */
export const KNOWN_PROTOCOL_VERSIONS = [
  "2026-07-28",
  "2025-11-25",
  "2025-06-18",
  "2025-03-26",
] as const;

/** A minimal, well-formed JSON-RPC body to elicit an auth challenge. */
export function initializeBody(protocolVersion = SPEC_VERSION): string {
  return JSON.stringify({
    jsonrpc: "2.0",
    id: 1,
    method: "initialize",
    params: {
      protocolVersion,
      capabilities: {},
      clientInfo: { name: "mcp-authcheck", version: TOOL_VERSION },
    },
  });
}

/**
 * `tools/list` is a read-only operation that, on a protected server, requires a
 * valid access token. We use it (not `initialize`, which is commonly an
 * unauthenticated handshake) as the canonical probe for token enforcement.
 */
export function toolsListBody(): string {
  return JSON.stringify({ jsonrpc: "2.0", id: 2, method: "tools/list", params: {} });
}

/**
 * RFC 9728 §3.1 Protected Resource Metadata well-known URL.
 *
 * For a resource with an empty path, the metadata lives at the origin root:
 *   https://host  ->  https://host/.well-known/oauth-protected-resource
 * For a resource with a path, the well-known suffix is inserted between the
 * host and the path (NOT appended at the end):
 *   https://host/mcp  ->  https://host/.well-known/oauth-protected-resource/mcp
 */
export function protectedResourceMetadataUrl(resource: string): string {
  return wellKnownWithPathInsertion(resource, "oauth-protected-resource");
}

/**
 * RFC 8414 §3.1 / MCP mandated fallback order for Authorization Server metadata.
 * Returns the URLs a compliant client MUST try, in order.
 *
 * For an issuer WITH a path (https://as/tenant1):
 *   1. https://as/.well-known/oauth-authorization-server/tenant1   (RFC 8414 insertion)
 *   2. https://as/.well-known/openid-configuration/tenant1         (OIDC insertion)
 *   3. https://as/tenant1/.well-known/openid-configuration         (OIDC append)
 * For an issuer WITHOUT a path (https://as):
 *   1. https://as/.well-known/oauth-authorization-server
 *   2. https://as/.well-known/openid-configuration
 */
export function authServerMetadataUrls(issuer: string): string[] {
  const u = new URL(issuer);
  const hasPath = u.pathname && u.pathname !== "/";
  if (!hasPath) {
    return [
      joinWellKnown(u, "oauth-authorization-server"),
      joinWellKnown(u, "openid-configuration"),
    ];
  }
  return [
    wellKnownWithPathInsertion(issuer, "oauth-authorization-server"),
    wellKnownWithPathInsertion(issuer, "openid-configuration"),
    oidcAppend(issuer),
  ];
}

/** https://host  ->  https://host/.well-known/<suffix> */
function joinWellKnown(u: URL, suffix: string): string {
  const out = new URL(u.toString());
  out.pathname = `/.well-known/${suffix}`;
  out.search = "";
  out.hash = "";
  return out.toString();
}

/** Insert `.well-known/<suffix>` between host and the (non-empty) path. */
function wellKnownWithPathInsertion(base: string, suffix: string): string {
  const u = new URL(base);
  const path = u.pathname === "/" ? "" : u.pathname.replace(/\/$/, "");
  const out = new URL(u.toString());
  out.pathname = `/.well-known/${suffix}${path}`;
  out.search = "";
  out.hash = "";
  return out.toString();
}

/** OIDC "append" form: https://host/path/.well-known/openid-configuration */
function oidcAppend(base: string): string {
  const u = new URL(base);
  const path = u.pathname.replace(/\/$/, "");
  const out = new URL(u.toString());
  out.pathname = `${path}/.well-known/openid-configuration`;
  out.search = "";
  out.hash = "";
  return out.toString();
}

/**
 * Canonicalize a resource identifier for comparison (B2): lowercase scheme and
 * host, drop the fragment, strip a trailing slash on an otherwise-empty path.
 * Deliberately does NOT lowercase the path (paths are case-sensitive).
 */
export function canonicalizeResource(url: string): string {
  const u = new URL(url);
  u.protocol = u.protocol.toLowerCase();
  u.hostname = u.hostname.toLowerCase();
  u.hash = "";
  if (u.pathname === "/") u.pathname = "";
  else u.pathname = u.pathname.replace(/\/$/, "");
  return u.toString().replace(/\/$/, "");
}

/** RFC 9728 §2 recommended/optional PRM fields we surface in B4. */
export const PRM_OPTIONAL_FIELDS = [
  "scopes_supported",
  "bearer_methods_supported",
  "resource_name",
  "resource_documentation",
  "jwks_uri",
  "resource_signing_alg_values_supported",
  "dpop_bound_access_tokens_required",
] as const;
