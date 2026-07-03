import { describe, it, expect } from "vitest";
import {
  protectedResourceMetadataUrl,
  authServerMetadataUrls,
  canonicalizeResource,
} from "./spec.js";

describe("protectedResourceMetadataUrl (RFC 9728 §3.1)", () => {
  it("root resource -> well-known at origin root", () => {
    expect(protectedResourceMetadataUrl("https://mcp.example.com")).toBe(
      "https://mcp.example.com/.well-known/oauth-protected-resource",
    );
  });

  it("pathful resource -> suffix inserted after host, before path", () => {
    expect(protectedResourceMetadataUrl("https://example.com/public/mcp")).toBe(
      "https://example.com/.well-known/oauth-protected-resource/public/mcp",
    );
  });

  it("strips trailing slash on the resource path", () => {
    expect(protectedResourceMetadataUrl("https://example.com/mcp/")).toBe(
      "https://example.com/.well-known/oauth-protected-resource/mcp",
    );
  });
});

describe("authServerMetadataUrls (RFC 8414 §3.1 + OIDC fallback order)", () => {
  it("pathless issuer -> 2 candidates in mandated order", () => {
    expect(authServerMetadataUrls("https://as.example.com")).toEqual([
      "https://as.example.com/.well-known/oauth-authorization-server",
      "https://as.example.com/.well-known/openid-configuration",
    ]);
  });

  it("pathful issuer -> 3 candidates: RFC8414-insert, OIDC-insert, OIDC-append", () => {
    expect(authServerMetadataUrls("https://as.example.com/tenant1")).toEqual([
      "https://as.example.com/.well-known/oauth-authorization-server/tenant1",
      "https://as.example.com/.well-known/openid-configuration/tenant1",
      "https://as.example.com/tenant1/.well-known/openid-configuration",
    ]);
  });
});

describe("canonicalizeResource (B2)", () => {
  it("lowercases scheme and host, drops fragment and trailing slash", () => {
    expect(canonicalizeResource("HTTPS://MCP.Example.com/mcp/#frag")).toBe(
      "https://mcp.example.com/mcp",
    );
  });

  it("preserves path case", () => {
    expect(canonicalizeResource("https://example.com/MyPath")).toBe(
      "https://example.com/MyPath",
    );
  });

  it("normalizes empty path", () => {
    expect(canonicalizeResource("https://example.com/")).toBe(
      "https://example.com",
    );
  });
});
