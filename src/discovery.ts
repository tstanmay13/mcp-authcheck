import { probe, parseWwwAuthenticate } from "./http.js";
import {
  initializeBody,
  toolsListBody,
  protectedResourceMetadataUrl,
  authServerMetadataUrls,
  SPEC_VERSION,
} from "./spec.js";
import type { Evidence, Probe } from "./types.js";

export interface GatherOptions {
  /** Include probes that require fixtures/create state (D2/D4/F2). Default false. */
  includeInvasive?: boolean;
  timeoutMs?: number;
  protocolVersion?: string;
}

/**
 * Probe an MCP server and assemble all evidence the checks reason over. This
 * is the only place that touches the network; checks are pure over the result.
 *
 * The sequence mirrors how a compliant MCP client discovers auth: hit the
 * endpoint unauthenticated, read the 401's WWW-Authenticate for the PRM URL,
 * fetch Protected Resource Metadata, then fetch each advertised Authorization
 * Server's metadata via the mandated well-known fallback order.
 */
export async function gather(
  target: string,
  opts: GatherOptions = {},
): Promise<Evidence> {
  const protocolVersion = opts.protocolVersion ?? SPEC_VERSION;
  const url = new URL(target);
  const origin = `${url.protocol}//${url.host}`;
  const probes: Probe[] = [];

  const commonHeaders = {
    "content-type": "application/json",
    "mcp-protocol-version": protocolVersion,
  };

  // --- Group A: unauthenticated challenge ---
  const unauth = await probe(target, {
    method: "POST",
    headers: commonHeaders,
    body: initializeBody(protocolVersion),
    timeoutMs: opts.timeoutMs,
    label: "unauthenticated POST initialize",
  });
  probes.push(unauth);

  // --- Protected-operation probes ---
  // tools/list is read-only and, on a protected server, requires a valid token.
  // We probe it both unauthenticated and with a bogus token to tell apart three
  // cases: a server that enforces auth (401), a public server (returns a result
  // to anyone), and a server that requires *a* token but never validates it.
  const unauthTools = await probe(target, {
    method: "POST",
    headers: commonHeaders,
    body: toolsListBody(),
    timeoutMs: opts.timeoutMs,
    label: "unauthenticated tools/list",
  });
  probes.push(unauthTools);

  const bogusTools = await probe(target, {
    method: "POST",
    headers: {
      ...commonHeaders,
      authorization: "Bearer mcp-authcheck.invalid.token",
    },
    body: toolsListBody(),
    timeoutMs: opts.timeoutMs,
    label: "bogus-token tools/list",
  });
  probes.push(bogusTools);

  // --- Group E1: Origin validation ---
  const badOrigin = await probe(target, {
    method: "POST",
    headers: {
      ...commonHeaders,
      origin: "https://evil.mcp-authcheck.example",
    },
    body: initializeBody(protocolVersion),
    timeoutMs: opts.timeoutMs,
    label: "POST with foreign Origin",
  });
  probes.push(badOrigin);

  // --- Group E2: legacy method rejection ---
  const getProbe = await probe(target, {
    method: "GET",
    headers: commonHeaders,
    timeoutMs: opts.timeoutMs,
    label: "GET on MCP endpoint",
  });
  probes.push(getProbe);

  // A WWW-Authenticate challenge can appear on any 401 — the unauthenticated
  // probe OR the bogus-token probe (servers with a public `initialize` only
  // challenge once a protected operation is hit with an invalid token). Collect
  // challenges from every probe so discovery and A2 see the richest one.
  const wwwAuth = probes.flatMap((p) =>
    parseWwwAuthenticate(p.response?.headers["www-authenticate"]),
  );

  // --- Group B: Protected Resource Metadata ---
  const prmFromHeader = wwwAuth
    .flatMap((c) => (c.params.resource_metadata ? [c.params.resource_metadata] : []))
    .at(0);
  const prmCandidates = uniq([
    ...(prmFromHeader ? [prmFromHeader] : []),
    protectedResourceMetadataUrl(target),
    protectedResourceMetadataUrl(origin),
  ]);

  let protectedResourceMetadata: Evidence["protectedResourceMetadata"];
  for (const prmUrl of prmCandidates) {
    const p = await probe(prmUrl, {
      timeoutMs: opts.timeoutMs,
      label: `fetch PRM ${prmUrl}`,
    });
    probes.push(p);
    if (
      p.response?.status === 200 &&
      p.response.json &&
      typeof p.response.json === "object"
    ) {
      protectedResourceMetadata = {
        url: prmUrl,
        doc: p.response.json as Record<string, unknown>,
      };
      break;
    }
  }

  // --- Group C: Authorization Server metadata, per advertised issuer ---
  const authServerMetadata: Evidence["authServerMetadata"] = [];
  const issuers = extractIssuers(protectedResourceMetadata?.doc);
  for (const issuer of issuers) {
    let asUrls: string[];
    try {
      asUrls = authServerMetadataUrls(issuer);
    } catch {
      continue; // not a valid URL; C-checks will note the malformed issuer
    }
    for (const asUrl of asUrls) {
      const p = await probe(asUrl, {
        timeoutMs: opts.timeoutMs,
        label: `fetch AS metadata ${asUrl}`,
      });
      probes.push(p);
      if (
        p.response?.status === 200 &&
        p.response.json &&
        typeof p.response.json === "object"
      ) {
        authServerMetadata.push({
          issuer,
          url: asUrl,
          doc: p.response.json as Record<string, unknown>,
        });
        break; // first hit in the fallback order wins for this issuer
      }
    }
  }

  return {
    target,
    origin,
    specVersion: protocolVersion,
    probes,
    protectedResourceMetadata,
    authServerMetadata,
    wwwAuthenticate: wwwAuth,
  };
}

function extractIssuers(prm: Record<string, unknown> | undefined): string[] {
  if (!prm) return [];
  const raw = prm.authorization_servers;
  if (!Array.isArray(raw)) return [];
  return raw.filter((x): x is string => typeof x === "string");
}

function uniq(xs: string[]): string[] {
  return [...new Set(xs)];
}
