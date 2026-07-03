import type { Probe, WwwAuthenticateChallenge } from "./types.js";

const DEFAULT_TIMEOUT_MS = 10_000;
const USER_AGENT = "mcp-authcheck (+https://github.com/tstanmay13/mcp-authcheck)";

export interface FetchOptions {
  method?: string;
  headers?: Record<string, string>;
  body?: string;
  timeoutMs?: number;
  label: string;
}

/**
 * Perform one HTTP exchange and record it as a Probe. Never throws: network
 * and timeout failures are captured in `probe.error` so a single unreachable
 * endpoint degrades one check rather than crashing the run.
 */
export async function probe(url: string, opts: FetchOptions): Promise<Probe> {
  const method = opts.method ?? "GET";
  const headers: Record<string, string> = {
    "user-agent": USER_AGENT,
    accept: "application/json, text/event-stream",
    ...opts.headers,
  };
  const started = Date.now();
  const controller = new AbortController();
  const timeout = setTimeout(
    () => controller.abort(),
    opts.timeoutMs ?? DEFAULT_TIMEOUT_MS,
  );

  const p: Probe = {
    label: opts.label,
    request: { method, url, headers },
    durationMs: 0,
  };

  try {
    const res = await fetch(url, {
      method,
      headers,
      body: opts.body,
      redirect: "manual",
      signal: controller.signal,
    });
    const text = await res.text();
    const respHeaders = headersToObject(res.headers);
    let json: unknown;
    const contentType = respHeaders["content-type"] ?? "";
    if (contentType.includes("json") && text.length > 0) {
      try {
        json = JSON.parse(text);
      } catch {
        // Non-JSON despite the header; leave json undefined, keep text.
      }
    } else if (contentType.includes("event-stream") && text.length > 0) {
      // MCP Streamable HTTP replies with SSE: `event: message\ndata: {json}`.
      // Extract the first data payload so checks can inspect the JSON-RPC body.
      json = parseSseData(text);
    }
    p.response = {
      status: res.status,
      headers: respHeaders,
      json,
      text,
    };
  } catch (err) {
    p.error =
      err instanceof Error
        ? err.name === "AbortError"
          ? `timeout after ${opts.timeoutMs ?? DEFAULT_TIMEOUT_MS}ms`
          : err.message
        : String(err);
  } finally {
    clearTimeout(timeout);
    p.durationMs = Date.now() - started;
  }
  return p;
}

/**
 * Extract and JSON-parse the first `data:` payload from an SSE stream. MCP
 * folds a single JSON-RPC message across one or more `data:` lines of one
 * event; we concatenate consecutive data lines and parse them.
 */
function parseSseData(text: string): unknown {
  const lines = text.split(/\r?\n/);
  let buf = "";
  for (const line of lines) {
    if (line.startsWith("data:")) {
      buf += line.slice(5).replace(/^ /, "");
    } else if (line.trim() === "" && buf) {
      break; // end of the first event
    }
  }
  if (!buf) return undefined;
  try {
    return JSON.parse(buf);
  } catch {
    return undefined;
  }
}

/**
 * Classify a parsed JSON-RPC response body. `result` means the request
 * succeeded; `error` means it was rejected at the JSON-RPC layer (e.g. an
 * auth error carried inside an HTTP 200); `none` means no JSON-RPC envelope.
 */
export function jsonRpcKind(body: unknown): "result" | "error" | "none" {
  if (!body || typeof body !== "object") return "none";
  const o = body as Record<string, unknown>;
  if ("result" in o) return "result";
  if ("error" in o) return "error";
  return "none";
}

function headersToObject(h: Headers): Record<string, string> {
  const out: Record<string, string> = {};
  h.forEach((value, key) => {
    // Lowercase keys for case-insensitive lookups by checks.
    out[key.toLowerCase()] = value;
  });
  return out;
}

/**
 * Parse an HTTP `WWW-Authenticate` header into its challenges per RFC 9110
 * §11.6.1: `challenge = auth-scheme [ 1*SP ( token68 / #auth-param ) ]`, where
 * `auth-param = token BWS "=" BWS ( token / quoted-string )`. A single header
 * value may carry multiple comma-separated challenges (e.g. `Bearer ..., Basic
 * ...`); we return each with its parsed params.
 *
 * This is a pragmatic parser sufficient for the Bearer challenges MCP servers
 * emit (RFC 6750 / RFC 9728). It handles quoted strings with escaped quotes
 * and tolerates the ambiguity of commas separating both params and challenges.
 */
export function parseWwwAuthenticate(
  value: string | undefined,
): WwwAuthenticateChallenge[] {
  if (!value) return [];
  const tokens = tokenize(value);
  const challenges: WwwAuthenticateChallenge[] = [];
  let current: WwwAuthenticateChallenge | undefined;

  for (let i = 0; i < tokens.length; i++) {
    const tok = tokens[i]!;
    const next = tokens[i + 1];
    // A bare token NOT followed by "=" starts a new auth-scheme.
    if (tok.type === "token" && (!next || next.type !== "eq")) {
      current = { scheme: tok.value, params: {} };
      challenges.push(current);
      continue;
    }
    // token "=" value  → an auth-param on the current challenge.
    if (tok.type === "token" && next?.type === "eq") {
      const valTok = tokens[i + 2];
      if (current && valTok && (valTok.type === "token" || valTok.type === "quoted")) {
        current.params[tok.value.toLowerCase()] = valTok.value;
        i += 2;
      }
    }
  }
  return challenges;
}

type Tok =
  | { type: "token"; value: string }
  | { type: "quoted"; value: string }
  | { type: "eq" }
  | { type: "comma" };

function tokenize(input: string): Tok[] {
  const toks: Tok[] = [];
  let i = 0;
  while (i < input.length) {
    const c = input[i]!;
    if (c === " " || c === "\t") {
      i++;
      continue;
    }
    if (c === ",") {
      toks.push({ type: "comma" });
      i++;
      continue;
    }
    if (c === "=") {
      toks.push({ type: "eq" });
      i++;
      continue;
    }
    if (c === '"') {
      // quoted-string with backslash escapes
      let j = i + 1;
      let out = "";
      while (j < input.length && input[j] !== '"') {
        if (input[j] === "\\" && j + 1 < input.length) {
          out += input[j + 1];
          j += 2;
        } else {
          out += input[j];
          j++;
        }
      }
      toks.push({ type: "quoted", value: out });
      i = j + 1;
      continue;
    }
    // token: any run of tchar (RFC 9110). We stop at delimiters.
    let j = i;
    while (j < input.length && !' \t,="'.includes(input[j]!)) j++;
    toks.push({ type: "token", value: input.slice(i, j) });
    i = j;
  }
  return toks;
}
