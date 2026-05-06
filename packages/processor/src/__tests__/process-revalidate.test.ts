import fs from "node:fs";
import os from "node:os";
import path from "node:path";
import { defineConfig, type FileRecord, setLoadedConfig } from "@deepsec/core";
import { afterEach, beforeEach, describe, expect, it } from "vitest";
import { process as processProject, revalidate } from "../index.js";
import { StubAgent } from "./stub-agent.js";

interface Fixture {
  tmp: string;
  targetRoot: string;
  projectId: string;
  dataRoot: string;
  recordPath: (relPath: string) => string;
  readRecord: (relPath: string) => FileRecord;
  writeRecord: (rec: FileRecord) => void;
}

function setupProject(opts: { projectId?: string; files?: string[] } = {}): Fixture {
  const projectId = opts.projectId ?? "test-proj";
  const tmp = fs.mkdtempSync(path.join(os.tmpdir(), "deepsec-proc-"));
  const targetRoot = path.join(tmp, "target");
  const dataRoot = path.join(tmp, "data");
  fs.mkdirSync(targetRoot, { recursive: true });
  fs.mkdirSync(path.join(dataRoot, projectId, "files"), { recursive: true });

  for (const f of opts.files ?? []) {
    const abs = path.join(targetRoot, f);
    fs.mkdirSync(path.dirname(abs), { recursive: true });
    fs.writeFileSync(abs, "// test file\n");
  }

  fs.writeFileSync(
    path.join(dataRoot, projectId, "project.json"),
    JSON.stringify({
      projectId,
      rootPath: targetRoot,
      createdAt: new Date().toISOString(),
    }),
  );

  process.env.DEEPSEC_DATA_ROOT = dataRoot;

  const recordPath = (relPath: string) =>
    path.join(dataRoot, projectId, "files", `${relPath}.json`);
  const readRecord = (relPath: string): FileRecord =>
    JSON.parse(fs.readFileSync(recordPath(relPath), "utf-8"));
  const writeRecord = (rec: FileRecord): void => {
    const p = recordPath(rec.filePath);
    fs.mkdirSync(path.dirname(p), { recursive: true });
    fs.writeFileSync(p, JSON.stringify(rec));
  };

  return { tmp, targetRoot, projectId, dataRoot, recordPath, readRecord, writeRecord };
}

function pendingRecord(projectId: string, filePath: string): FileRecord {
  return {
    filePath,
    projectId,
    candidates: [
      {
        vulnSlug: "auth-bypass",
        lineNumbers: [1],
        snippet: "// stub",
        matchedPattern: "test pattern",
      },
    ],
    lastScannedAt: new Date().toISOString(),
    lastScannedRunId: "scan-fixture",
    fileHash: "fixture-hash",
    findings: [],
    analysisHistory: [],
    status: "pending",
  };
}

describe("processor with stub agent", () => {
  let prevDataRoot: string | undefined;

  beforeEach(() => {
    prevDataRoot = process.env.DEEPSEC_DATA_ROOT;
  });

  afterEach(() => {
    if (prevDataRoot === undefined) delete process.env.DEEPSEC_DATA_ROOT;
    else process.env.DEEPSEC_DATA_ROOT = prevDataRoot;
    setLoadedConfig(defineConfig({ projects: [] }));
  });

  it("process() runs the agent, persists findings + AnalysisEntry, marks files analyzed", async () => {
    const fx = setupProject({ files: ["app.ts"] });
    fx.writeRecord(pendingRecord(fx.projectId, "app.ts"));

    const stub = new StubAgent();
    setLoadedConfig(
      defineConfig({
        projects: [{ id: fx.projectId, root: fx.targetRoot }],
        plugins: [{ name: "stub-plugin", agents: [stub] }],
      }),
    );

    const result = await processProject({
      projectId: fx.projectId,
      agentType: "stub",
      concurrency: 1,
    });

    expect(result.findingCount).toBe(1);
    expect(result.analysisCount).toBe(1);
    expect(stub.calls.investigateCalls).toHaveLength(1);
    expect(stub.calls.investigateCalls[0].batch).toHaveLength(1);

    const rec = fx.readRecord("app.ts");
    expect(rec.status).toBe("analyzed");
    expect(rec.findings).toHaveLength(1);
    expect(rec.findings[0].severity).toBe("HIGH");
    expect(rec.findings[0].title).toBe("stub finding for app.ts");
    expect(rec.analysisHistory).toHaveLength(1);
    expect(rec.analysisHistory[0].agentType).toBe("stub");
    expect(rec.analysisHistory[0].findingCount).toBe(1);
    expect(rec.lockedByRunId).toBeFalsy();
  });

  it("process() respects --limit", async () => {
    const fx = setupProject({ files: ["a.ts", "b.ts", "c.ts"] });
    fx.writeRecord(pendingRecord(fx.projectId, "a.ts"));
    fx.writeRecord(pendingRecord(fx.projectId, "b.ts"));
    fx.writeRecord(pendingRecord(fx.projectId, "c.ts"));

    const stub = new StubAgent();
    setLoadedConfig(
      defineConfig({
        projects: [{ id: fx.projectId, root: fx.targetRoot }],
        plugins: [{ name: "stub", agents: [stub] }],
      }),
    );

    await processProject({
      projectId: fx.projectId,
      agentType: "stub",
      concurrency: 1,
      limit: 2,
    });

    const statuses = ["a.ts", "b.ts", "c.ts"].map((f) => fx.readRecord(f).status);
    const analyzed = statuses.filter((s) => s === "analyzed").length;
    expect(analyzed).toBe(2);
    expect(statuses).toContain("pending");
  });

  it("process() skips already-analyzed files unless --reinvestigate", async () => {
    const fx = setupProject({ files: ["a.ts"] });
    const rec = pendingRecord(fx.projectId, "a.ts");
    rec.status = "analyzed";
    rec.analysisHistory = [
      {
        runId: "earlier",
        investigatedAt: new Date().toISOString(),
        durationMs: 1,
        agentType: "stub",
        model: "stub",
        modelConfig: {},
        findingCount: 0,
        usage: {
          inputTokens: 1,
          outputTokens: 1,
          cacheReadInputTokens: 0,
          cacheCreationInputTokens: 0,
        },
      },
    ];
    fx.writeRecord(rec);

    const stub = new StubAgent();
    setLoadedConfig(
      defineConfig({
        projects: [{ id: fx.projectId, root: fx.targetRoot }],
        plugins: [{ name: "stub", agents: [stub] }],
      }),
    );

    const result = await processProject({
      projectId: fx.projectId,
      agentType: "stub",
      concurrency: 1,
    });

    expect(result.analysisCount).toBe(0);
    expect(stub.calls.investigateCalls).toHaveLength(0);
  });

  it("process() throws a clear error when project root does not exist", async () => {
    const fx = setupProject({ files: ["app.ts"] });
    fx.writeRecord(pendingRecord(fx.projectId, "app.ts"));
    // Wipe the target root so the existence check fires.
    fs.rmSync(fx.targetRoot, { recursive: true, force: true });

    setLoadedConfig(
      defineConfig({
        projects: [{ id: fx.projectId, root: fx.targetRoot }],
        plugins: [{ name: "stub", agents: [new StubAgent()] }],
      }),
    );

    await expect(
      processProject({
        projectId: fx.projectId,
        agentType: "stub",
        concurrency: 1,
      }),
    ).rejects.toThrow(/Project root does not exist/);
  });

  it("process() does NOT reclaim a record locked by a still-running other run", async () => {
    // Race regression: two concurrent process() invocations against the
    // same project would both pick up the same `processing` record and
    // clobber each other's writes. Reclaim should only fire when the
    // owning lock is genuinely abandoned (run done/error/missing or
    // STALE_LOCK_MS expired).
    const fx = setupProject({ files: ["app.ts"] });

    // Pretend an "other" run is mid-investigation: fresh lock, run-meta
    // says phase=running.
    const otherRunId = "20260101000000-otheraaaaaaaaaaa";
    const lockedRec = pendingRecord(fx.projectId, "app.ts");
    lockedRec.status = "processing";
    lockedRec.lockedByRunId = otherRunId;
    lockedRec.lockedAt = new Date().toISOString();
    fx.writeRecord(lockedRec);
    fs.mkdirSync(path.join(fx.dataRoot, fx.projectId, "runs"), { recursive: true });
    fs.writeFileSync(
      path.join(fx.dataRoot, fx.projectId, "runs", `${otherRunId}.json`),
      JSON.stringify({
        runId: otherRunId,
        projectId: fx.projectId,
        rootPath: fx.targetRoot,
        createdAt: new Date().toISOString(),
        type: "process",
        phase: "running",
        stats: {},
      }),
    );

    const stub = new StubAgent();
    setLoadedConfig(
      defineConfig({
        projects: [{ id: fx.projectId, root: fx.targetRoot }],
        plugins: [{ name: "stub", agents: [stub] }],
      }),
    );

    const result = await processProject({
      projectId: fx.projectId,
      agentType: "stub",
      concurrency: 1,
    });

    // Lock respected — agent never invoked, file untouched.
    expect(stub.calls.investigateCalls).toHaveLength(0);
    expect(result.analysisCount).toBe(0);
    const after = fx.readRecord("app.ts");
    expect(after.status).toBe("processing");
    expect(after.lockedByRunId).toBe(otherRunId);
  });

  it("process() reclaims a record whose owning run finished (phase=done)", async () => {
    const fx = setupProject({ files: ["app.ts"] });

    // Same setup but the owning run's meta says phase=done — its lock
    // is abandoned and safe to reclaim.
    const deadRunId = "20260101000000-deadaaaaaaaaaaaa";
    const lockedRec = pendingRecord(fx.projectId, "app.ts");
    lockedRec.status = "processing";
    lockedRec.lockedByRunId = deadRunId;
    lockedRec.lockedAt = new Date().toISOString();
    fx.writeRecord(lockedRec);
    fs.mkdirSync(path.join(fx.dataRoot, fx.projectId, "runs"), { recursive: true });
    fs.writeFileSync(
      path.join(fx.dataRoot, fx.projectId, "runs", `${deadRunId}.json`),
      JSON.stringify({
        runId: deadRunId,
        projectId: fx.projectId,
        rootPath: fx.targetRoot,
        createdAt: new Date().toISOString(),
        completedAt: new Date().toISOString(),
        type: "process",
        phase: "done",
        stats: {},
      }),
    );

    const stub = new StubAgent();
    setLoadedConfig(
      defineConfig({
        projects: [{ id: fx.projectId, root: fx.targetRoot }],
        plugins: [{ name: "stub", agents: [stub] }],
      }),
    );

    const result = await processProject({
      projectId: fx.projectId,
      agentType: "stub",
      concurrency: 1,
    });

    expect(result.analysisCount).toBe(1);
    expect(stub.calls.investigateCalls).toHaveLength(1);
  });

  it("process() captures refusals from the agent into AnalysisEntry", async () => {
    const fx = setupProject({ files: ["app.ts"] });
    fx.writeRecord(pendingRecord(fx.projectId, "app.ts"));

    const stub = new StubAgent({
      async *investigateImpl(params) {
        return {
          results: params.batch.map((r) => ({ filePath: r.filePath, findings: [] })),
          meta: {
            durationMs: 1,
            refusal: { refused: true, reason: "stub refusal" },
            usage: {
              inputTokens: 1,
              outputTokens: 1,
              cacheReadInputTokens: 0,
              cacheCreationInputTokens: 0,
            },
          },
        };
      },
    });
    setLoadedConfig(
      defineConfig({
        projects: [{ id: fx.projectId, root: fx.targetRoot }],
        plugins: [{ name: "stub", agents: [stub] }],
      }),
    );

    await processProject({
      projectId: fx.projectId,
      agentType: "stub",
      concurrency: 1,
    });

    const rec = fx.readRecord("app.ts");
    expect(rec.findings).toHaveLength(0);
    expect(rec.analysisHistory[0].refusal?.refused).toBe(true);
    expect(rec.analysisHistory[0].refusal?.reason).toBe("stub refusal");
  });

  it("revalidate() attaches verdicts to existing findings", async () => {
    const fx = setupProject({ files: ["app.ts"] });
    const rec = pendingRecord(fx.projectId, "app.ts");
    rec.status = "analyzed";
    rec.findings = [
      {
        severity: "HIGH",
        vulnSlug: "auth-bypass",
        title: "missing auth on /admin",
        description: "no withAuthentication wrapper",
        lineNumbers: [10],
        recommendation: "wrap with withAuthentication",
        confidence: "high",
      },
    ];
    rec.analysisHistory = [
      {
        runId: "earlier",
        investigatedAt: new Date().toISOString(),
        durationMs: 1,
        agentType: "stub",
        model: "stub",
        modelConfig: {},
        findingCount: 1,
      },
    ];
    fx.writeRecord(rec);

    const stub = new StubAgent();
    setLoadedConfig(
      defineConfig({
        projects: [{ id: fx.projectId, root: fx.targetRoot }],
        plugins: [{ name: "stub", agents: [stub] }],
      }),
    );

    await revalidate({
      projectId: fx.projectId,
      agentType: "stub",
      concurrency: 1,
    });

    expect(stub.calls.revalidateCalls).toHaveLength(1);
    const after = fx.readRecord("app.ts");
    expect(after.findings).toHaveLength(1);
    expect(after.findings[0].revalidation?.verdict).toBe("true-positive");
    expect(after.findings[0].revalidation?.reasoning).toBe("stub: confirmed");
  });

  it("revalidate() skips findings that already have a verdict unless --force", async () => {
    const fx = setupProject({ files: ["app.ts"] });
    const rec = pendingRecord(fx.projectId, "app.ts");
    rec.status = "analyzed";
    rec.findings = [
      {
        severity: "HIGH",
        vulnSlug: "auth-bypass",
        title: "already revalidated",
        description: "x",
        lineNumbers: [1],
        recommendation: "x",
        confidence: "high",
        revalidation: {
          verdict: "true-positive",
          reasoning: "previous run",
          revalidatedAt: new Date().toISOString(),
          runId: "earlier",
          model: "stub",
        },
      },
    ];
    fx.writeRecord(rec);

    const stub = new StubAgent();
    setLoadedConfig(
      defineConfig({
        projects: [{ id: fx.projectId, root: fx.targetRoot }],
        plugins: [{ name: "stub", agents: [stub] }],
      }),
    );

    await revalidate({
      projectId: fx.projectId,
      agentType: "stub",
      concurrency: 1,
    });

    expect(stub.calls.revalidateCalls).toHaveLength(0);
  });
});
