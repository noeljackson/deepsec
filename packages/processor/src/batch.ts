import path from "node:path";
import type { FileRecord } from "@deepsec/core";

const DEFAULT_BATCH_SIZE = 5;

/**
 * Groups file records by directory, then splits into batches of at most `maxSize`.
 * Files in the same directory are likely related and benefit from shared context.
 */
export function batchCandidates(
  records: FileRecord[],
  maxSize: number = DEFAULT_BATCH_SIZE,
): FileRecord[][] {
  // Group by directory
  const byDir = new Map<string, FileRecord[]>();
  for (const r of records) {
    const dir = path.dirname(r.filePath);
    const group = byDir.get(dir) ?? [];
    group.push(r);
    byDir.set(dir, group);
  }

  // Split groups that exceed maxSize, merge small groups
  const batches: FileRecord[][] = [];
  let currentBatch: FileRecord[] = [];

  for (const group of byDir.values()) {
    if (group.length >= maxSize) {
      for (let i = 0; i < group.length; i += maxSize) {
        batches.push(group.slice(i, i + maxSize));
      }
    } else if (currentBatch.length + group.length > maxSize) {
      if (currentBatch.length > 0) {
        batches.push(currentBatch);
      }
      currentBatch = [...group];
    } else {
      currentBatch.push(...group);
    }
  }

  if (currentBatch.length > 0) {
    batches.push(currentBatch);
  }

  return batches;
}
