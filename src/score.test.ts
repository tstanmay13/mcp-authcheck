import { describe, it, expect } from "vitest";
import { computeGrade, summarize, gradeMeetsMin } from "./score.js";
import type { CheckResult, Severity, CheckStatus } from "./types.js";

function r(
  severity: Severity,
  status: CheckStatus,
  id = `${severity}-${status}`,
): CheckResult {
  return {
    id,
    title: id,
    status,
    severity,
    requirement: "MUST",
    message: "",
    reference: { spec: "test", url: "https://example.com" },
  };
}

describe("computeGrade", () => {
  it("all passing => 100 / A", () => {
    const g = computeGrade([r("critical", "pass"), r("high", "pass"), r("low", "pass")]);
    expect(g.score).toBe(100);
    expect(g.letter).toBe("A");
  });

  it("info-severity checks never affect the score", () => {
    const g = computeGrade([r("critical", "pass"), r("info", "fail"), r("info", "warn")]);
    expect(g.score).toBe(100);
  });

  it("skip and error are excluded from the denominator", () => {
    const g = computeGrade([r("high", "pass"), r("high", "skip"), r("critical", "error")]);
    expect(g.score).toBe(100);
  });

  it("warn earns half weight", () => {
    // one high pass (20) + one high warn (10) => 30/40 = 75
    const g = computeGrade([r("high", "pass"), r("high", "warn")]);
    expect(g.score).toBe(75);
  });

  it("a critical failure caps the letter to F regardless of score", () => {
    // 9 passing highs (180) + 1 failing critical (0/40) => 180/220 = 82 => would be B
    const results = [
      ...Array.from({ length: 9 }, (_, i) => r("high", "pass", `h${i}`)),
      r("critical", "fail"),
    ];
    const g = computeGrade(results);
    expect(g.score).toBeGreaterThanOrEqual(80); // numerically a B...
    expect(g.letter).toBe("F"); // ...but gated to F by the critical failure
  });

  it("a high failure caps the letter to C at best", () => {
    // many passing lows keep the score high, one failing high gates to C
    const results = [
      ...Array.from({ length: 30 }, (_, i) => r("low", "pass", `l${i}`)),
      r("high", "fail"),
    ];
    const g = computeGrade(results);
    expect(g.score).toBeGreaterThanOrEqual(80);
    expect(g.letter).toBe("C");
  });

  it("a medium failure does NOT cap the letter (no gate)", () => {
    const results = [
      ...Array.from({ length: 9 }, (_, i) => r("critical", "pass", `c${i}`)),
      r("medium", "fail"),
    ];
    const g = computeGrade(results);
    // 360/370 ≈ 97 => A, no gate for medium
    expect(g.letter).toBe("A");
  });

  it("empty / all-skip is N/A, not a false zero", () => {
    expect(computeGrade([])).toEqual({ score: null, letter: "N/A" });
    expect(computeGrade([r("high", "skip")])).toEqual({ score: null, letter: "N/A" });
  });

  it("public and unknown posture are N/A regardless of results", () => {
    expect(computeGrade([r("critical", "fail")], "public").letter).toBe("N/A");
    expect(computeGrade([r("critical", "fail")], "unknown").letter).toBe("N/A");
  });
});

describe("gradeMeetsMin", () => {
  it("passes when the grade is at or above the threshold", () => {
    expect(gradeMeetsMin("A", "A")).toBe(true);
    expect(gradeMeetsMin("A", "C")).toBe(true);
    expect(gradeMeetsMin("C", "C")).toBe(true);
  });
  it("fails when below the threshold", () => {
    expect(gradeMeetsMin("F", "B")).toBe(false);
    expect(gradeMeetsMin("C", "B")).toBe(false);
  });
  it("a public server (N/A) always passes", () => {
    expect(gradeMeetsMin("N/A", "A")).toBe(true);
  });
  it("is case-insensitive on the threshold", () => {
    expect(gradeMeetsMin("B", "b")).toBe(true);
  });
});

describe("summarize", () => {
  it("counts every status", () => {
    const s = summarize([
      r("high", "pass"),
      r("high", "pass"),
      r("critical", "fail"),
      r("low", "warn"),
      r("info", "info"),
      r("high", "skip"),
      r("critical", "error"),
    ]);
    expect(s).toEqual({ pass: 2, fail: 1, warn: 1, info: 1, skip: 1, error: 1 });
  });
});
