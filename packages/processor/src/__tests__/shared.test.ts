import { describe, expect, it } from "vitest";
import {
  isTransientError,
  parseInvestigateResults,
  parseRefusalReport,
  parseRevalidateVerdicts,
} from "../agents/shared.js";

describe("isTransientError", () => {
  it("flags 5xx, 429, eager_input_streaming, ECONNRESET", () => {
    expect(isTransientError("HTTP 503 Service Unavailable")).toBe(true);
    expect(isTransientError("HTTP 429 too many requests")).toBe(true);
    expect(isTransientError("Extra inputs are not permitted: eager_input_streaming")).toBe(true);
    expect(isTransientError("ECONNRESET fetch failed")).toBe(true);
    expect(isTransientError("rate-limit hit")).toBe(true);
    expect(isTransientError("overloaded")).toBe(true);
  });

  it("doesn't flag obvious permanent errors", () => {
    expect(isTransientError("ENOENT no such file")).toBe(false);
    expect(isTransientError("invalid api key")).toBe(false);
  });
});

describe("parseRefusalReport", () => {
  it("parses fenced JSON with refused: true", () => {
    const raw =
      '```json\n{"refused": true, "reason": "policy", "skipped": [{"filePath":"a.ts","reason":"x"}]}\n```';
    const r = parseRefusalReport(raw);
    expect(r?.refused).toBe(true);
    expect(r?.reason).toBe("policy");
    expect(r?.skipped).toEqual([{ filePath: "a.ts", reason: "x" }]);
  });

  it("parses bare JSON with refused: false", () => {
    const r = parseRefusalReport('{"refused": false, "skipped": []}');
    expect(r?.refused).toBe(false);
    expect(r?.skipped).toEqual([]);
  });

  it("falls back to heuristic on non-JSON refusal text", () => {
    const r = parseRefusalReport("I can't analyze this content.");
    expect(r?.refused).toBe(true);
    expect(r?.reason).toContain("heuristic");
  });

  it("returns undefined on empty input", () => {
    expect(parseRefusalReport("")).toBeUndefined();
  });
});

describe("parseInvestigateResults", () => {
  const batch = [{ filePath: "a.ts" } as any, { filePath: "b.ts" } as any];

  it("matches results to batch files; fills missing with empty findings", () => {
    const text = '```json\n[{"filePath":"a.ts","findings":[{"severity":"HIGH"}]}]\n```';
    const out = parseInvestigateResults(text, batch);
    expect(out.find((r) => r.filePath === "a.ts")?.findings.length).toBe(1);
    expect(out.find((r) => r.filePath === "b.ts")?.findings).toEqual([]);
  });

  it("throws on parse failure (fail-loud, never silently empty)", () => {
    // Silently returning empty findings on malformed JSON would mask
    // model truncation, prompt-injection-driven non-JSON output, and
    // gateway splices — all of which are indistinguishable from a
    // legitimate clean result. The processor's batch-level catch
    // converts this throw into batchesFailed++ + status=error.
    expect(() => parseInvestigateResults("not JSON at all", batch)).toThrow(
      /wasn't a parseable JSON findings array/,
    );
  });

  it("throws when the JSON parses but isn't an array", () => {
    expect(() => parseInvestigateResults('```json\n{"oops":"object"}\n```', batch)).toThrow(
      /not an array/,
    );
  });
});

describe("parseRevalidateVerdicts", () => {
  it("parses verdicts from fenced JSON", () => {
    const text =
      '```json\n[{"filePath":"a.ts","title":"x","verdict":"true-positive","reasoning":"r"}]\n```';
    const v = parseRevalidateVerdicts(text);
    expect(v).toHaveLength(1);
    expect(v[0].verdict).toBe("true-positive");
  });

  it("throws on parse failure", () => {
    expect(() => parseRevalidateVerdicts("garbage")).toThrow(/wasn't parseable JSON/);
  });
});
