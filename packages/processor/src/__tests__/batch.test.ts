import type { FileRecord } from "@deepsec/core";
import { describe, expect, it } from "vitest";
import { batchCandidates } from "../batch.js";

function makeRecord(filePath: string): FileRecord {
  return {
    filePath,
    projectId: "test",
    candidates: [
      {
        vulnSlug: "xss",
        lineNumbers: [1],
        snippet: "code",
        matchedPattern: "test",
      },
    ],
    lastScannedAt: "2026-04-01T00:00:00Z",
    lastScannedRunId: "run1",
    fileHash: "abc",
    findings: [],
    analysisHistory: [],
    status: "pending",
  };
}

describe("batchCandidates", () => {
  it("groups files by directory", () => {
    const records = [
      makeRecord("src/api/a.ts"),
      makeRecord("src/api/b.ts"),
      makeRecord("src/lib/c.ts"),
    ];
    const batches = batchCandidates(records, 10);
    expect(batches.length).toBe(1);
    expect(batches[0].length).toBe(3);
  });

  it("splits large groups", () => {
    const records = Array.from({ length: 15 }, (_, i) => makeRecord(`src/api/file${i}.ts`));
    const batches = batchCandidates(records, 5);
    expect(batches.length).toBe(3);
    expect(batches[0].length).toBe(5);
  });

  it("returns empty array for no records", () => {
    expect(batchCandidates([], 10)).toEqual([]);
  });

  it("respects max batch size across directories", () => {
    const records = [
      makeRecord("src/a/1.ts"),
      makeRecord("src/a/2.ts"),
      makeRecord("src/a/3.ts"),
      makeRecord("src/b/1.ts"),
      makeRecord("src/b/2.ts"),
      makeRecord("src/b/3.ts"),
    ];
    const batches = batchCandidates(records, 4);
    expect(batches.length).toBe(2);
    for (const batch of batches) {
      expect(batch.length).toBeLessThanOrEqual(4);
    }
  });
});
