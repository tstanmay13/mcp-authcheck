import { describe, it, expect } from "vitest";
import { runChecks } from "./checks.js";
import { parseWwwAuthenticate } from "./http.js";
import type { Evidence, Probe, CheckResult } from "./types.js";

/** Build a Probe with a JSON/text response for fixtures. */
function probe(
  label: string,
  status: number,
  headers: Record<string, string> = {},
  json?: unknown,
): Probe {
  return {
    label,
    request: { method: "POST", url: "https://mcp.example.com/mcp", headers: {} },
    response: { status, headers, json },
    durationMs: 1,
  };
}

const PRM_DOC = {
  resource: "https://mcp.example.com/mcp",
  authorization_servers: ["https://auth.example.com"],
  scopes_supported: ["read", "write"],
  bearer_methods_supported: ["header"],
};

const AS_DOC = {
  issuer: "https://auth.example.com",
  response_types_supported: ["code"],
  authorization_endpoint: "https://auth.example.com/authorize",
  token_endpoint: "https://auth.example.com/token",
  jwks_uri: "https://auth.example.com/jwks",
  code_challenge_methods_supported: ["S256"],
  client_id_metadata_document_supported: true,
  authorization_response_iss_parameter_supported: true,
};

/** A fully-compliant server fixture. */
function compliantEvidence(): Evidence {
  const wwwAuth = parseWwwAuthenticate(
    'Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp", scope="read"',
  );
  return {
    target: "https://mcp.example.com/mcp",
    origin: "https://mcp.example.com",
    wwwAuthenticate: wwwAuth,
    protectedResourceMetadata: {
      url: "https://mcp.example.com/.well-known/oauth-protected-resource/mcp",
      doc: PRM_DOC,
    },
    authServerMetadata: [
      { issuer: "https://auth.example.com", url: "https://auth.example.com/.well-known/oauth-authorization-server", doc: AS_DOC },
    ],
    probes: [
      probe("unauthenticated POST initialize", 401, {
        "www-authenticate":
          'Bearer resource_metadata="https://mcp.example.com/.well-known/oauth-protected-resource/mcp", scope="read"',
      }),
      probe("unauthenticated tools/list", 401, {
        "www-authenticate": 'Bearer error="invalid_token"',
      }),
      probe("bogus-token tools/list", 401, {
        "www-authenticate": 'Bearer error="invalid_token"',
      }),
      probe("POST with foreign Origin", 403),
      probe("GET on MCP endpoint", 405),
    ],
  };
}

function byId(results: CheckResult[], id: string): CheckResult | undefined {
  return results.find((r) => r.id === id || r.id.startsWith(`${id}[`));
}

describe("runChecks — compliant server", () => {
  const results = runChecks(compliantEvidence());

  it("passes all the critical checks", () => {
    for (const id of ["A1", "A2", "B1", "B3", "C1", "D1"]) {
      expect(byId(results, id)?.status, id).toBe("pass");
    }
  });

  it("passes PKCE, HTTPS, issuer-match, required-fields", () => {
    for (const id of ["B2", "C2", "C3", "C4", "C5"]) {
      expect(byId(results, id)?.status, id).toBe("pass");
    }
  });

  it("has no failures", () => {
    expect(results.filter((r) => r.status === "fail")).toEqual([]);
  });
});

describe("runChecks — token validation (D1)", () => {
  it("fails critically when an invalid token yields a successful tools/list result", () => {
    const e = compliantEvidence();
    e.probes = e.probes.map((p) =>
      p.label === "bogus-token tools/list"
        ? probe("bogus-token tools/list", 200, {}, { jsonrpc: "2.0", id: 2, result: { tools: [] } })
        : p,
    );
    const d1 = byId(runChecks(e), "D1")!;
    expect(d1.status).toBe("fail");
    expect(d1.severity).toBe("critical");
    expect(d1.message).toMatch(/does not validate/i);
  });

  it("treats a JSON-RPC error inside HTTP 200 as a medium warn (rejected, wrong layer)", () => {
    const e = compliantEvidence();
    e.probes = e.probes.map((p) =>
      p.label === "bogus-token tools/list"
        ? probe("bogus-token tools/list", 200, {}, { jsonrpc: "2.0", id: 2, error: { code: -32001, message: "unauthorized" } })
        : p,
    );
    const d1 = byId(runChecks(e), "D1")!;
    expect(d1.status).toBe("warn");
    expect(d1.severity).toBe("medium");
  });

  it("passes when the invalid token is rejected with 401", () => {
    const d1 = byId(runChecks(compliantEvidence()), "D1")!;
    expect(d1.status).toBe("pass");
  });
});

describe("runChecks — missing Protected Resource Metadata", () => {
  it("fails B1 and skips downstream PRM/AS checks", () => {
    const e = compliantEvidence();
    e.protectedResourceMetadata = undefined;
    e.authServerMetadata = [];
    const results = runChecks(e);
    expect(byId(results, "B1")?.status).toBe("fail");
    expect(byId(results, "B2")?.status).toBe("skip");
    expect(byId(results, "C1")?.status).toBe("skip");
  });
});

describe("runChecks — public server (no auth)", () => {
  it("marks A1 informational and skips auth checks when unauthenticated calls succeed", () => {
    const okResult = { jsonrpc: "2.0", id: 1, result: { tools: [] } };
    const e: Evidence = {
      target: "https://public.example.com/mcp",
      origin: "https://public.example.com",
      wwwAuthenticate: [],
      authServerMetadata: [],
      probes: [
        probe("unauthenticated POST initialize", 200, {}, okResult),
        probe("unauthenticated tools/list", 200, {}, okResult),
        probe("bogus-token tools/list", 200, {}, okResult),
        probe("POST with foreign Origin", 200),
        probe("GET on MCP endpoint", 200),
      ],
    };
    const results = runChecks(e);
    expect(byId(results, "A1")?.status).toBe("info");
    expect(byId(results, "A2")?.status).toBe("skip");
    expect(byId(results, "B1")?.status).toBe("skip");
    expect(byId(results, "D1")?.status).toBe("skip");
  });
});

describe("runChecks — degraded auth-server metadata", () => {
  it("fails C4 when PKCE S256 is not advertised", () => {
    const e = compliantEvidence();
    const doc = { ...AS_DOC };
    delete (doc as Record<string, unknown>).code_challenge_methods_supported;
    e.authServerMetadata = [{ issuer: "https://auth.example.com", url: "x", doc }];
    expect(byId(runChecks(e), "C4")?.status).toBe("fail");
  });

  it("fails C2 on issuer mismatch (mix-up defense)", () => {
    const e = compliantEvidence();
    e.authServerMetadata = [
      { issuer: "https://auth.example.com", url: "x", doc: { ...AS_DOC, issuer: "https://evil.example.com" } },
    ];
    expect(byId(runChecks(e), "C2")?.status).toBe("fail");
  });

  it("fails C5 when an endpoint is not HTTPS", () => {
    const e = compliantEvidence();
    e.authServerMetadata = [
      { issuer: "https://auth.example.com", url: "x", doc: { ...AS_DOC, token_endpoint: "http://auth.example.com/token" } },
    ];
    expect(byId(runChecks(e), "C5")?.status).toBe("fail");
  });
});
