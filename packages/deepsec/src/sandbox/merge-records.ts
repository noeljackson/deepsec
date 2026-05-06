import fs from "node:fs";
import path from "node:path";
import type { AnalysisEntry, FileRecord, Finding } from "@deepsec/core";

/**
 * Tarball extraction is `cwd=dataDir(projectId)`, so file records live
 * under `<destDir>/files/**.json`. We only merge those — run metadata
 * (`runs/*.json`) is unique per runId, so the tar overwrite is safe there.
 */
const FILES_SUBDIR = "files";

/**
 * Snapshot all existing file records under `<destDir>/files/` into a map
 * keyed by their path relative to `destDir` (e.g. `"files/src/foo.ts.json"`).
 *
 * Called BEFORE tar extraction so we have the host's pre-extraction state
 * to merge against once the tarball lands.
 *
 * Best-effort: malformed JSON is skipped silently rather than aborting the
 * download — a corrupt host record shouldn't block a sandbox upload, and
 * the incoming version will replace it via the normal extract path.
 */
export function snapshotFileRecords(destDir: string): Map<string, FileRecord> {
  const out = new Map<string, FileRecord>();
  const filesRoot = path.join(destDir, FILES_SUBDIR);
  if (!fs.existsSync(filesRoot)) return out;

  const stack: string[] = [filesRoot];
  while (stack.length > 0) {
    const dir = stack.pop()!;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) {
        stack.push(full);
      } else if (e.isFile() && e.name.endsWith(".json")) {
        try {
          const raw = JSON.parse(fs.readFileSync(full, "utf-8"));
          out.set(path.relative(destDir, full), raw as FileRecord);
        } catch {
          // skip malformed
        }
      }
    }
  }
  return out;
}

/**
 * Merge two FileRecords representing the same file but written by
 * concurrent sandbox uploads.
 *
 * The race we're fixing: sandbox A and sandbox B both snapshotted the
 * host data dir at slightly different times. Each appended its own
 * `analysisHistory` entry locally, then uploaded a full tarball. Without
 * merging, whichever tarball is extracted last overwrites the other's
 * history — and in practice we observed entire codex runs disappearing
 * from per-file `analysisHistory` despite being recorded in `runs/*.json`.
 *
 * Merge strategy:
 *   - `analysisHistory`: union by `runId` (each run is globally unique).
 *     For the same runId on both sides, prefer `incoming` since the
 *     tarball is the more recent serialization.
 *   - `findings`: union by `(vulnSlug, normalized title)` signature, the
 *     same key `process()` uses to dedupe re-runs. For matching findings,
 *     merge field-by-field so a `revalidation` / `triage` set on either
 *     side survives.
 *   - `gitInfo`: prefer whichever side has it set — enrich runs only
 *     populate, never clear, so losing it across an extract is real loss.
 *   - `status`: "analyzed" wins over anything else (a finished run on
 *     either side means the file is analyzed). Otherwise prefer incoming.
 *   - `lockedByRunId` / `lockedAt`: prefer incoming; the per-batch loop
 *     in `process()` is the authoritative writer.
 *   - Scan-time fields (`candidates`, `lastScannedAt`, `lastScannedRunId`,
 *     `fileHash`): prefer incoming. Concurrent process/revalidate runs
 *     don't touch these — if they differ, the difference came from a
 *     scan run that has its own non-racing lifecycle.
 */
export function mergeFileRecord(host: FileRecord, incoming: FileRecord): FileRecord {
  const historyByRunId = new Map<string, AnalysisEntry>();
  for (const entry of host.analysisHistory ?? []) {
    historyByRunId.set(entry.runId, entry);
  }
  for (const entry of incoming.analysisHistory ?? []) {
    historyByRunId.set(entry.runId, entry);
  }
  const mergedHistory = Array.from(historyByRunId.values()).sort(
    (a, b) => new Date(a.investigatedAt).getTime() - new Date(b.investigatedAt).getTime(),
  );

  const findingsBySig = new Map<string, Finding>();
  for (const f of host.findings ?? []) {
    findingsBySig.set(findingSignature(f), f);
  }
  for (const f of incoming.findings ?? []) {
    const sig = findingSignature(f);
    const existing = findingsBySig.get(sig);
    findingsBySig.set(sig, existing ? mergeFinding(existing, f) : f);
  }
  const mergedFindings = Array.from(findingsBySig.values());

  const status =
    host.status === "analyzed" || incoming.status === "analyzed" ? "analyzed" : incoming.status;

  return {
    ...incoming,
    gitInfo: incoming.gitInfo ?? host.gitInfo,
    findings: mergedFindings,
    analysisHistory: mergedHistory,
    status,
  };
}

function findingSignature(f: Finding): string {
  return `${f.vulnSlug ?? ""}::${(f.title ?? "").trim().toLowerCase()}`;
}

function mergeFinding(host: Finding, incoming: Finding): Finding {
  return {
    ...host,
    ...incoming,
    revalidation: incoming.revalidation ?? host.revalidation,
    triage: incoming.triage ?? host.triage,
    producedByRunId: host.producedByRunId ?? incoming.producedByRunId,
  };
}

/**
 * After tar extraction, walk `<destDir>/files/**.json` and re-write any
 * record that also existed in `hostSnapshot` with a merged version.
 *
 * Files that didn't exist on the host before extraction are left
 * untouched (they're the sandbox's contribution). Files that existed on
 * the host but are missing from the tarball are also untouched (the
 * sandbox didn't change them this poll).
 *
 * Returns the number of records that were merge-rewritten.
 */
export function mergeAfterExtract(destDir: string, hostSnapshot: Map<string, FileRecord>): number {
  if (hostSnapshot.size === 0) return 0;
  const filesRoot = path.join(destDir, FILES_SUBDIR);
  if (!fs.existsSync(filesRoot)) return 0;

  let merged = 0;
  const stack: string[] = [filesRoot];
  while (stack.length > 0) {
    const dir = stack.pop()!;
    let entries: fs.Dirent[];
    try {
      entries = fs.readdirSync(dir, { withFileTypes: true });
    } catch {
      continue;
    }
    for (const e of entries) {
      const full = path.join(dir, e.name);
      if (e.isDirectory()) {
        stack.push(full);
        continue;
      }
      if (!(e.isFile() && e.name.endsWith(".json"))) continue;
      const rel = path.relative(destDir, full);
      const host = hostSnapshot.get(rel);
      if (!host) continue;

      let incoming: FileRecord;
      try {
        incoming = JSON.parse(fs.readFileSync(full, "utf-8")) as FileRecord;
      } catch {
        continue;
      }
      const out = mergeFileRecord(host, incoming);
      fs.writeFileSync(full, JSON.stringify(out, null, 2) + "\n");
      merged++;
    }
  }
  return merged;
}
