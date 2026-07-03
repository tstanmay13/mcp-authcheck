import { describe, it, expect } from "vitest";
import { parseWwwAuthenticate } from "./http.js";

describe("parseWwwAuthenticate", () => {
  it("returns empty for undefined", () => {
    expect(parseWwwAuthenticate(undefined)).toEqual([]);
  });

  it("parses a bare scheme", () => {
    expect(parseWwwAuthenticate("Bearer")).toEqual([
      { scheme: "Bearer", params: {} },
    ]);
  });

  it("parses Bearer with quoted params (RFC 6750 / 9728 shape)", () => {
    const out = parseWwwAuthenticate(
      'Bearer realm="mcp", error="invalid_token", resource_metadata="https://api.example.com/.well-known/oauth-protected-resource"',
    );
    expect(out).toHaveLength(1);
    expect(out[0]!.scheme).toBe("Bearer");
    expect(out[0]!.params.realm).toBe("mcp");
    expect(out[0]!.params.error).toBe("invalid_token");
    expect(out[0]!.params.resource_metadata).toBe(
      "https://api.example.com/.well-known/oauth-protected-resource",
    );
  });

  it("lowercases param names but preserves values", () => {
    const out = parseWwwAuthenticate('Bearer Realm="Keep-Case"');
    expect(out[0]!.params.realm).toBe("Keep-Case");
  });

  it("parses multiple challenges in one header", () => {
    const out = parseWwwAuthenticate('Bearer realm="a", Basic realm="b"');
    expect(out.map((c) => c.scheme)).toEqual(["Bearer", "Basic"]);
    expect(out[0]!.params.realm).toBe("a");
    expect(out[1]!.params.realm).toBe("b");
  });

  it("handles escaped quotes in quoted-string", () => {
    const out = parseWwwAuthenticate('Bearer error_description="say \\"hi\\""');
    expect(out[0]!.params.error_description).toBe('say "hi"');
  });

  it("handles unquoted token values", () => {
    const out = parseWwwAuthenticate("Bearer error=invalid_token");
    expect(out[0]!.params.error).toBe("invalid_token");
  });
});
