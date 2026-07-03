import type { Check, CheckResult, Evidence } from "./types.js";
import { canonicalizeResource, PRM_OPTIONAL_FIELDS } from "./spec.js";
import { jsonRpcKind } from "./http.js";

/**
 * The check catalog. Each check is a pure function over gathered Evidence,
 * returning one or more results. Checks never touch the network. IDs and
 * severities match docs/check-catalog.md.
 */

const SPEC_AUTH =
  "https://modelcontextprotocol.io/specification/draft/basic/authorization";
const SPEC_DISCOVERY =
  "https://modelcontextprotocol.io/specification/draft/basic/authorization/authorization-server-discovery";
const SPEC_TRANSPORT =
  "https://modelcontextprotocol.io/specification/draft/basic/transports/streamable-http";
const RFC9728 = "https://datatracker.ietf.org/doc/html/rfc9728";
const RFC8414 = "https://datatracker.ietf.org/doc/html/rfc8414";
const RFC9207 = "https://datatracker.ietf.org/doc/html/rfc9207";

// --- Group A: unauthenticated challenge ---

const a1_unauthenticated401: Check = (e) => {
  const init = findProbe(e, "unauthenticated POST initialize");
  const tools = findProbe(e, "unauthenticated tools/list");
  const title = "Rejects unauthenticated requests with 401";
  const ref = { spec: "MCP authorization §Token Handling", url: SPEC_AUTH };

  if ((init?.error || init?.response === undefined) && (tools?.error || tools?.response === undefined)) {
    return result({
      id: "A1",
      title,
      status: "error",
      severity: "critical",
      requirement: "MUST",
      message: `could not reach endpoint: ${init?.error ?? tools?.error ?? "no response"}`,
      reference: ref,
    });
  }

  const p = posture(e);
  if (p === "protected") {
    const challengedProbe = isChallenge(init?.response?.status)
      ? "initialize"
      : isChallenge(tools?.response?.status)
        ? "tools/list"
        : "discovery metadata";
    return result({
      id: "A1",
      title,
      status: "pass",
      severity: "critical",
      requirement: "MUST",
      message: `server challenges unauthenticated requests (via ${challengedProbe})`,
      reference: ref,
      evidence: {
        initStatus: init?.response?.status,
        toolsStatus: tools?.response?.status,
      },
    });
  }
  if (p === "public") {
    return result({
      id: "A1",
      title,
      status: "info",
      severity: "critical",
      requirement: "MUST",
      message:
        "server returns results to unauthenticated callers — it appears to be public (no authorization). The auth-conformance checks below do not apply.",
      reference: ref,
      evidence: {
        initStatus: init?.response?.status,
        toolsStatus: tools?.response?.status,
      },
    });
  }
  return result({
    id: "A1",
    title,
    status: "warn",
    severity: "critical",
    requirement: "MUST",
    message: `could not determine auth posture (initialize=${init?.response?.status}, tools/list=${tools?.response?.status}); the server neither challenged nor returned a clear result`,
    reference: ref,
    evidence: {
      initStatus: init?.response?.status,
      toolsStatus: tools?.response?.status,
    },
  });
};

const a2_wwwAuthenticate: Check = (e) => {
  const title = "401 challenge advertises resource_metadata (RFC 9728 §5.1)";
  const ref = { spec: "RFC 9728 §5.1", section: "5.1", url: RFC9728 };
  const bearers = (e.wwwAuthenticate ?? []).filter(
    (c) => c.scheme.toLowerCase() === "bearer",
  );
  // Prefer the challenge that carries resource_metadata (a server may emit one
  // Bearer challenge on 401 that has it and another elsewhere that does not).
  const withRm = bearers.find((b) => b.params.resource_metadata);

  if (withRm) {
    const rm = withRm.params.resource_metadata!;
    const valid = isHttpUrl(rm);
    return result({
      id: "A2",
      title,
      status: valid ? "pass" : "fail",
      severity: "critical",
      requirement: "MUST",
      message: valid
        ? `challenge advertises resource_metadata (${rm})`
        : `resource_metadata is not a valid URL: ${rm}`,
      reference: ref,
      evidence: { resource_metadata: rm },
    });
  }
  if (bearers.length > 0) {
    // Severity depends on whether the client can discover auth another way: if
    // Protected Resource Metadata is reachable at the well-known path anyway,
    // the missing header hint is a real gap but not disqualifying (high); if no
    // PRM exists at all, clients cannot discover authorization → critical.
    const prmDiscoverable = !!e.protectedResourceMetadata;
    return result({
      id: "A2",
      title,
      status: "fail",
      severity: prmDiscoverable ? "high" : "critical",
      requirement: "MUST",
      message: prmDiscoverable
        ? "a Bearer challenge is present but omits resource_metadata; clients relying on the RFC 9728 header hint will not find the PRM (though it is reachable at the well-known path)"
        : "a Bearer challenge is present but omits resource_metadata, and no PRM is served — clients cannot discover authorization",
      reference: ref,
      evidence: { challenges: bearers },
      remediation:
        'Add resource_metadata="<PRM URL>" to the 401 Bearer challenge.',
    });
  }
  return result({
    id: "A2",
    title,
    status: isProtected(e) ? "fail" : "skip",
    severity: "critical",
    requirement: "MUST",
    message: isProtected(e)
      ? "no Bearer WWW-Authenticate challenge was returned on any unauthenticated/invalid-token response"
      : "server is not protected; no challenge expected",
    reference: ref,
    evidence: { challenges: e.wwwAuthenticate },
    remediation:
      'On 401, send `WWW-Authenticate: Bearer resource_metadata="<PRM URL>"`.',
  });
};

const a3_scopeHint: Check = (e) => {
  const bearer = (e.wwwAuthenticate ?? []).find(
    (c) => c.scheme.toLowerCase() === "bearer",
  );
  const hasScope = !!bearer?.params.scope;
  return result({
    id: "A3",
    title: "WWW-Authenticate advertises scope (optional)",
    status: hasScope ? "pass" : isProtected(e) ? "info" : "skip",
    severity: "info",
    requirement: "MAY",
    message: hasScope
      ? `advertises scope="${bearer!.params.scope}"`
      : "no scope hint in challenge (optional per RFC 6750 §3)",
    reference: { spec: "RFC 6750 §3", url: SPEC_AUTH },
  });
};

// --- Group B: Protected Resource Metadata (RFC 9728) ---

const b1_prmServed: Check = (e) => {
  if (!isProtected(e)) {
    return result({
      id: "B1",
      title: "Protected Resource Metadata endpoint served",
      status: "skip",
      severity: "critical",
      requirement: "MUST",
      message: "server is not protected; PRM not applicable",
      reference: { spec: "RFC 9728 §3", url: RFC9728 },
    });
  }
  const prm = e.protectedResourceMetadata;
  return result({
    id: "B1",
    title: "Protected Resource Metadata endpoint served",
    status: prm ? "pass" : "fail",
    severity: "critical",
    requirement: "MUST",
    message: prm
      ? `PRM served at ${prm.url}`
      : "no Protected Resource Metadata document found at the advertised or well-known URL",
    reference: { spec: "RFC 9728 §3", section: "3", url: RFC9728 },
    evidence: prm ? { url: prm.url } : undefined,
    remediation:
      "Serve RFC 9728 metadata (200 application/json) at /.well-known/oauth-protected-resource.",
  });
};

const b2_prmResource: Check = (e) => {
  const prm = e.protectedResourceMetadata;
  if (!prm) return skip("B2", "PRM resource field present and canonical", "high", RFC9728);
  const resource = prm.doc.resource;
  if (typeof resource !== "string") {
    return result({
      id: "B2",
      title: "PRM resource field present and canonical",
      status: "fail",
      severity: "high",
      requirement: "MUST",
      message: "PRM is missing the required `resource` field",
      reference: { spec: "RFC 9728 §2", url: RFC9728 },
      remediation: "Add the required `resource` field naming this server's canonical URI.",
    });
  }
  let matches = false;
  try {
    matches =
      canonicalizeResource(resource) === canonicalizeResource(e.target) ||
      canonicalizeResource(resource) === canonicalizeResource(e.origin);
  } catch {
    matches = false;
  }
  return result({
    id: "B2",
    title: "PRM resource field present and canonical",
    status: matches ? "pass" : "warn",
    severity: "high",
    requirement: "MUST",
    message: matches
      ? `resource matches the server URI (${resource})`
      : `resource "${resource}" does not canonically match the probed URL — verify this is intentional`,
    reference: { spec: "RFC 9728 §2", url: RFC9728 },
    evidence: { resource, target: e.target },
    remediation: matches
      ? undefined
      : "The `resource` value MUST be the canonical URI clients use to reach this server (scheme+host, no fragment).",
  });
};

const b3_authServers: Check = (e) => {
  const prm = e.protectedResourceMetadata;
  if (!prm) return skip("B3", "PRM authorization_servers non-empty", "critical", SPEC_DISCOVERY);
  const arr = prm.doc.authorization_servers;
  const ok = Array.isArray(arr) && arr.length > 0 && arr.every((x) => typeof x === "string");
  return result({
    id: "B3",
    title: "PRM authorization_servers non-empty",
    status: ok ? "pass" : "fail",
    severity: "critical",
    requirement: "MUST",
    message: ok
      ? `advertises ${(arr as string[]).length} authorization server(s)`
      : "PRM is missing a non-empty authorization_servers array (MANDATORY per MCP)",
    reference: { spec: "MCP authorization-server-discovery", url: SPEC_DISCOVERY },
    evidence: { authorization_servers: arr },
    remediation:
      "Include an `authorization_servers` array with at least one issuer identifier URL.",
  });
};

const b4_prmOptionalFields: Check = (e) => {
  const prm = e.protectedResourceMetadata;
  if (!prm) return skip("B4", "PRM recommended fields present", "low", RFC9728);
  const present = PRM_OPTIONAL_FIELDS.filter((f) => f in prm.doc);
  const missing = PRM_OPTIONAL_FIELDS.filter((f) => !(f in prm.doc));
  return result({
    id: "B4",
    title: "PRM recommended fields present",
    status: present.length > 0 ? "pass" : "info",
    severity: "info",
    requirement: "SHOULD",
    message:
      present.length > 0
        ? `present: ${present.join(", ")}${missing.length ? `; absent: ${missing.join(", ")}` : ""}`
        : "no recommended optional fields present (all are optional)",
    reference: { spec: "RFC 9728 §2", url: RFC9728 },
    evidence: { present, missing },
  });
};

// --- Group C: Authorization Server metadata (RFC 8414 / OIDC), per issuer ---

const cChecks: Check = (e) => {
  const prm = e.protectedResourceMetadata;
  const issuers = Array.isArray(prm?.doc.authorization_servers)
    ? (prm!.doc.authorization_servers as unknown[]).filter(
        (x): x is string => typeof x === "string",
      )
    : [];
  if (issuers.length === 0) {
    return [
      skip("C1", "AS metadata discoverable", "critical", SPEC_DISCOVERY),
    ];
  }

  const out: CheckResult[] = [];
  for (const issuer of issuers) {
    const as = e.authServerMetadata.find((m) => m.issuer === issuer);
    const label = shortIssuer(issuer);

    // C1: discoverable
    out.push(
      result({
        id: `C1[${label}]`,
        title: "AS metadata discoverable via mandated fallback order",
        status: as ? "pass" : "fail",
        severity: "critical",
        requirement: "MUST",
        message: as
          ? `discovered at ${as.url}`
          : `no RFC 8414 or OIDC metadata found for issuer ${issuer}`,
        reference: { spec: "MCP authorization-server-discovery", url: SPEC_DISCOVERY },
        evidence: { issuer },
        remediation:
          "Serve RFC 8414 metadata at /.well-known/oauth-authorization-server (or OIDC discovery).",
      }),
    );
    if (!as) continue;
    const doc = as.doc;

    // C2: issuer matches
    const docIssuer = typeof doc.issuer === "string" ? doc.issuer : undefined;
    out.push(
      result({
        id: `C2[${label}]`,
        title: "AS metadata issuer exactly matches",
        status: docIssuer === issuer ? "pass" : "fail",
        severity: "high",
        requirement: "MUST",
        message:
          docIssuer === issuer
            ? "issuer matches the advertised authorization server"
            : `issuer mismatch: document says "${docIssuer}", expected "${issuer}" (mix-up defense)`,
        reference: { spec: "RFC 8414 §3.3", section: "3.3", url: RFC8414 },
        evidence: { expected: issuer, got: docIssuer },
      }),
    );

    // C3: required fields
    const required = ["issuer", "response_types_supported", "authorization_endpoint", "token_endpoint"];
    const missingReq = required.filter((f) => !(f in doc));
    out.push(
      result({
        id: `C3[${label}]`,
        title: "AS metadata required fields present",
        status: missingReq.length === 0 ? "pass" : "fail",
        severity: "high",
        requirement: "MUST",
        message:
          missingReq.length === 0
            ? "all required RFC 8414 fields present"
            : `missing required field(s): ${missingReq.join(", ")}`,
        reference: { spec: "RFC 8414 §2", section: "2", url: RFC8414 },
        evidence: { missing: missingReq },
      }),
    );

    // C4: PKCE S256
    const methods = doc.code_challenge_methods_supported;
    const hasS256 = Array.isArray(methods) && methods.includes("S256");
    out.push(
      result({
        id: `C4[${label}]`,
        title: "PKCE S256 advertised",
        status: hasS256 ? "pass" : "fail",
        severity: "high",
        requirement: "MUST",
        message: hasS256
          ? "advertises code_challenge_methods_supported containing S256"
          : "does not advertise PKCE S256 (OAuth 2.1 requires PKCE)",
        reference: { spec: "OAuth 2.1 §7.5.2 / RFC 8414", url: RFC8414 },
        evidence: { code_challenge_methods_supported: methods },
        remediation: "Advertise and enforce PKCE with S256.",
      }),
    );

    // C5: HTTPS endpoints
    const endpointKeys = [
      "authorization_endpoint",
      "token_endpoint",
      "jwks_uri",
      "registration_endpoint",
      "revocation_endpoint",
      "introspection_endpoint",
    ];
    const nonHttps = endpointKeys
      .map((k) => [k, doc[k]] as const)
      .filter(([, v]) => typeof v === "string" && !isHttpsUrl(v as string));
    out.push(
      result({
        id: `C5[${label}]`,
        title: "All AS endpoints served over HTTPS",
        status: nonHttps.length === 0 ? "pass" : "fail",
        severity: "high",
        requirement: "MUST",
        message:
          nonHttps.length === 0
            ? "all advertised endpoints use https"
            : `non-HTTPS endpoint(s): ${nonHttps.map(([k]) => k).join(", ")}`,
        reference: { spec: "MCP authorization §Communication Security", url: SPEC_AUTH },
        evidence: { nonHttps: Object.fromEntries(nonHttps) },
      }),
    );

    // C6: registration capability (info)
    const cimd = doc.client_id_metadata_document_supported === true;
    const dcr = typeof doc.registration_endpoint === "string";
    out.push(
      result({
        id: `C6[${label}]`,
        title: "Client registration capability advertised",
        status: cimd || dcr ? "pass" : "info",
        severity: "info",
        requirement: "MAY",
        message: cimd
          ? "supports CIMD (client_id_metadata_document_supported)"
          : dcr
            ? "supports Dynamic Client Registration (RFC 7591; deprecated in 2026-07-28 but allowed)"
            : "no CIMD or DCR advertised — clients must be pre-registered",
        reference: { spec: "MCP client-registration", url: SPEC_DISCOVERY },
        evidence: { cimd, dcr },
      }),
    );

    // C7: RFC 9207 iss support
    const iss = doc.authorization_response_iss_parameter_supported === true;
    out.push(
      result({
        id: `C7[${label}]`,
        title: "RFC 9207 issuer-response parameter supported",
        status: iss ? "pass" : "warn",
        severity: "low",
        requirement: "SHOULD",
        message: iss
          ? "advertises authorization_response_iss_parameter_supported"
          : "does not advertise RFC 9207 iss support (SHOULD; mix-up defense, trending to MUST)",
        reference: { spec: "RFC 9207 §2.3", section: "2.3", url: RFC9207 },
        evidence: { authorization_response_iss_parameter_supported: doc.authorization_response_iss_parameter_supported },
      }),
    );
  }
  return out;
};

// --- Group D1: bogus token rejection ---

const d1_rejectsBogusToken: Check = (e) => {
  const title = "Validates access tokens (rejects a bogus token)";
  const ref = { spec: "MCP authorization §Token Handling", url: SPEC_AUTH };
  if (!isProtected(e)) {
    return skip("D1", title, "critical", SPEC_AUTH);
  }
  const p = findProbe(e, "bogus-token tools/list");
  const status = p?.response?.status;
  if (p?.error || status === undefined) {
    return result({
      id: "D1",
      title,
      status: "error",
      severity: "critical",
      requirement: "MUST",
      message: p?.error ?? "no response",
      reference: ref,
    });
  }
  const bearerError = parseBearerError(p?.response?.headers["www-authenticate"]);
  const kind = jsonRpcKind(p?.response?.json);

  // The decisive signal is the BODY, not just the status: MCP servers can
  // carry an auth rejection inside an HTTP 200 JSON-RPC error. We probe the
  // protected `tools/list` operation with an invalid token.
  //   - rejected (401/403, or a JSON-RPC error) → the token was validated: pass.
  //   - a successful tools/list *result* → the server returned protected data
  //     to an invalid token: it does not validate tokens on this read op.
  //   - other (session-required 400, etc.) → inconclusive: warn.
  if (status === 401 || status === 403) {
    return result({
      id: "D1",
      title,
      status: "pass",
      severity: "critical",
      requirement: "MUST",
      message: `invalid token rejected with ${status}${bearerError ? ` (error="${bearerError}")` : ""}`,
      reference: ref,
      evidence: { status, error: bearerError },
    });
  }
  if (kind === "result") {
    return result({
      id: "D1",
      title,
      status: "fail",
      severity: "critical",
      requirement: "MUST",
      message: `server returned a successful tools/list result to a request bearing an INVALID token (HTTP ${status}) — it does not validate access tokens on this read operation`,
      reference: ref,
      evidence: { status, jsonRpc: "result" },
      remediation:
        "Validate the access token (signature, expiry, and audience) on every authenticated operation and reject invalid tokens with 401.",
    });
  }
  if (kind === "error") {
    return result({
      id: "D1",
      title,
      status: "warn",
      severity: "medium",
      requirement: "MUST",
      message: `invalid token rejected via a JSON-RPC error inside HTTP ${status} — safe, but the spec requires an HTTP 401 with WWW-Authenticate`,
      reference: { spec: "MCP authorization §Token Handling / RFC 6750 §3.1", url: SPEC_AUTH },
      evidence: { status, jsonRpc: "error" },
      remediation:
        'Return HTTP 401 with `WWW-Authenticate: Bearer error="invalid_token"` rather than a 2xx with a JSON-RPC error.',
    });
  }
  return result({
    id: "D1",
    title,
    status: "warn",
    severity: "medium",
    requirement: "MUST",
    message: `inconclusive: invalid-token tools/list returned HTTP ${status} with no JSON-RPC result or error (the server may require an established session first)`,
    reference: ref,
    evidence: { status },
  });
};

// --- Group E: transport hardening ---

const e1_originValidation: Check = (e) => {
  const p = findProbe(e, "POST with foreign Origin");
  const status = p?.response?.status;
  if (p?.error || status === undefined) {
    return skip("E1", "Validates Origin header (DNS-rebinding defense)", "low", SPEC_TRANSPORT);
  }
  // The MCP Origin-validation MUST primarily protects locally-bound servers from
  // DNS-rebinding; for a remote SaaS server the threat model is weak, so this is
  // scored low and never gates the grade. 403 is spec-ideal; any 4xx is safe; a
  // 2xx success to a foreign Origin is the only real signal, and only informative.
  const ok = status === 403;
  const safe = status >= 400 && status < 500;
  return result({
    id: "E1",
    title: "Validates Origin header (DNS-rebinding defense)",
    status: ok ? "pass" : safe ? "pass" : "warn",
    severity: "low",
    requirement: "SHOULD",
    message: ok
      ? "foreign Origin rejected with 403"
      : safe
        ? `foreign Origin got ${status} (rejected)`
        : `foreign Origin got ${status} — no Origin validation observed (low risk for a remote server; matters most for locally-bound servers)`,
    reference: { spec: "MCP streamable-http §Security", url: SPEC_TRANSPORT },
    evidence: { status },
    remediation: ok || safe
      ? undefined
      : "If this server can be reached from a browser, validate the Origin header and reject unrecognized origins.",
  });
};

const e2_legacyMethod: Check = (e) => {
  const p = findProbe(e, "GET on MCP endpoint");
  const status = p?.response?.status;
  if (p?.error || status === undefined) {
    return skip("E2", "Rejects GET on the MCP endpoint (2026-07-28)", "low", SPEC_TRANSPORT);
  }
  // Version-gated: pre-2026 servers legitimately support GET streams. We only
  // note this as informational unless the server declared 2026-07-28.
  const ok = status === 405;
  return result({
    id: "E2",
    title: "Rejects GET on the MCP endpoint (2026-07-28)",
    status: ok ? "pass" : "info",
    severity: "low",
    requirement: "SHOULD",
    message: ok
      ? "GET correctly rejected with 405"
      : `GET returned ${status} — expected 405 under 2026-07-28 (legal under earlier revisions that support GET streams)`,
    reference: { spec: "MCP streamable-http §Earlier Revisions", url: SPEC_TRANSPORT },
    evidence: { status },
  });
};

/** The ordered catalog. */
export const CHECKS: Check[] = [
  a1_unauthenticated401,
  a2_wwwAuthenticate,
  a3_scopeHint,
  b1_prmServed,
  b2_prmResource,
  b3_authServers,
  b4_prmOptionalFields,
  cChecks,
  d1_rejectsBogusToken,
  e1_originValidation,
  e2_legacyMethod,
];

export function runChecks(e: Evidence): CheckResult[] {
  return CHECKS.flatMap((c) => {
    const r = c(e);
    return Array.isArray(r) ? r : [r];
  });
}

// --- helpers ---

function result(r: CheckResult): CheckResult {
  return r;
}

function skip(
  id: string,
  title: string,
  severity: CheckResult["severity"],
  url: string,
): CheckResult {
  return {
    id,
    title,
    status: "skip",
    severity,
    requirement: "MUST",
    message: "prerequisite not met (no protected-resource metadata to evaluate)",
    reference: { spec: "n/a", url },
  };
}

export type Posture = "protected" | "public" | "unknown";

/**
 * Determine whether a server enforces authorization, so auth-conformance checks
 * only run where they apply. This keys off *protected operations*, not the
 * `initialize` handshake alone (which many servers intentionally leave open):
 *
 *  - protected: it challenges (401/403, or a WWW-Authenticate) on an
 *    unauthenticated request, or it advertises Protected Resource Metadata.
 *  - public: an unauthenticated `tools/list` (or `initialize`) returns a
 *    successful JSON-RPC result — anyone can use it, so auth MUSTs don't apply.
 *  - unknown: neither signal is clear (e.g. it demands a session id first).
 */
export function posture(e: Evidence): Posture {
  const init = findProbe(e, "unauthenticated POST initialize");
  const tools = findProbe(e, "unauthenticated tools/list");

  if (
    isChallenge(init?.response?.status) ||
    isChallenge(tools?.response?.status) ||
    (e.wwwAuthenticate ?? []).length > 0 ||
    e.protectedResourceMetadata
  ) {
    return "protected";
  }
  if (
    jsonRpcKind(tools?.response?.json) === "result" ||
    jsonRpcKind(init?.response?.json) === "result"
  ) {
    return "public";
  }
  return "unknown";
}

function isProtected(e: Evidence): boolean {
  return posture(e) === "protected";
}

function isChallenge(status: number | undefined): boolean {
  return status === 401 || status === 403;
}

function findProbe(e: Evidence, label: string) {
  return e.probes.find((p) => p.label === label);
}

function isHttpUrl(s: string): boolean {
  try {
    const u = new URL(s);
    return u.protocol === "http:" || u.protocol === "https:";
  } catch {
    return false;
  }
}

function isHttpsUrl(s: string): boolean {
  try {
    return new URL(s).protocol === "https:";
  } catch {
    return false;
  }
}

/** A compact label for an issuer URL, used to disambiguate per-AS check IDs. */
function shortIssuer(issuer: string): string {
  try {
    return new URL(issuer).host;
  } catch {
    return issuer;
  }
}

function parseBearerError(header: string | undefined): string | undefined {
  if (!header) return undefined;
  const m = header.match(/error="?([a-z_]+)"?/i);
  return m?.[1];
}
