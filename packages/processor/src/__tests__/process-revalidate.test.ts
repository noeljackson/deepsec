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

  it("process() divides batch-level cost / tokens evenly across files in the batch", async () => {
    // Repro for the metrics inflation bug: agent.investigate() reports
    // one cost / token total for the whole batch (one API call covers N
    // files), and we used to stamp that total onto every file's
    // analysisHistory entry. Summing per-file entries then over-counted
    // by ~batch size in `metrics`.
    const fx = setupProject({ files: ["a.ts", "b.ts", "c.ts", "d.ts"] });
    fx.writeRecord(pendingRecord(fx.projectId, "a.ts"));
    fx.writeRecord(pendingRecord(fx.projectId, "b.ts"));
    fx.writeRecord(pendingRecord(fx.projectId, "c.ts"));
    fx.writeRecord(pendingRecord(fx.projectId, "d.ts"));

    const stub = new StubAgent({
      async *investigateImpl(params) {
        return {
          results: params.batch.map((r) => ({ filePath: r.filePath, findings: [] })),
          meta: {
            durationMs: 4000,
            durationApiMs: 2000,
            numTurns: 8,
            costUsd: 4.0,
            usage: {
              inputTokens: 4000,
              outputTokens: 400,
              cacheReadInputTokens: 800,
              cacheCreationInputTokens: 200,
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
      batchSize: 4,
    });

    const records = ["a.ts", "b.ts", "c.ts", "d.ts"].map((f) => fx.readRecord(f));
    // Each file gets a quarter of the batch-level numbers.
    for (const r of records) {
      expect(r.analysisHistory).toHaveLength(1);
      const h = r.analysisHistory[0];
      expect(h.costUsd).toBe(1.0);
      expect(h.usage?.inputTokens).toBe(1000);
      expect(h.usage?.outputTokens).toBe(100);
      expect(h.usage?.cacheReadInputTokens).toBe(200);
      expect(h.usage?.cacheCreationInputTokens).toBe(50);
      expect(h.durationMs).toBe(1000);
      expect(h.durationApiMs).toBe(500);
      expect(h.numTurns).toBe(2);
      expect(h.phase).toBe("process");
    }
    // Sum across per-file entries reproduces the batch total.
    const sumCost = records.reduce((s, r) => s + (r.analysisHistory[0].costUsd ?? 0), 0);
    expect(sumCost).toBeCloseTo(4.0, 6);
  });

  it("revalidate() pushes a per-file analysisHistory entry tagged phase='revalidate' with divided cost", async () => {
    const fx = setupProject({ files: ["x.ts", "y.ts"] });
    for (const f of ["x.ts", "y.ts"]) {
      const r = pendingRecord(fx.projectId, f);
      r.status = "analyzed";
      r.findings = [
        {
          severity: "HIGH",
          vulnSlug: "auth-bypass",
          title: `bug in ${f}`,
          description: "x",
          lineNumbers: [1],
          recommendation: "x",
          confidence: "high",
        },
      ];
      r.analysisHistory = [
        {
          runId: "earlier",
          investigatedAt: new Date().toISOString(),
          durationMs: 1,
          agentType: "stub",
          model: "stub",
          modelConfig: {},
          findingCount: 1,
          phase: "process",
        },
      ];
      fx.writeRecord(r);
    }

    const stub = new StubAgent({
      async *revalidateImpl(params) {
        return {
          verdicts: params.batch.flatMap((rec) =>
            rec.findings.map((f) => ({
              filePath: rec.filePath,
              title: f.title,
              verdict: "true-positive" as const,
              reasoning: "stub",
            })),
          ),
          meta: {
            durationMs: 2000,
            costUsd: 0.5,
            usage: {
              inputTokens: 2000,
              outputTokens: 200,
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

    await revalidate({
      projectId: fx.projectId,
      agentType: "stub",
      concurrency: 1,
      batchSize: 2,
    });

    const xs = fx.readRecord("x.ts");
    const ys = fx.readRecord("y.ts");

    // Each file now has the original process entry + a new revalidate entry.
    for (const r of [xs, ys]) {
      expect(r.analysisHistory).toHaveLength(2);
      const reval = r.analysisHistory.find((h) => h.phase === "revalidate");
      expect(reval).toBeDefined();
      expect(reval?.costUsd).toBe(0.25);
      expect(reval?.usage?.inputTokens).toBe(1000);
      expect(reval?.findingCount).toBe(1);
      expect(reval?.agentType).toBe("stub");
    }
  });

  it("process(--reinvestigate N) ignores phase='revalidate' entries when deciding what's already done", async () => {
    // A revalidate run shouldn't satisfy a process wave: a file that
    // only has a revalidate entry for agent X still needs a fresh
    // process pass for agent X on wave N.
    const fx = setupProject({ files: ["a.ts"] });
    const rec = pendingRecord(fx.projectId, "a.ts");
    rec.status = "analyzed";
    rec.analysisHistory = [
      {
        runId: "reval-only",
        investigatedAt: new Date().toISOString(),
        durationMs: 1,
        agentType: "stub",
        model: "stub",
        modelConfig: {},
        findingCount: 0,
        phase: "revalidate",
        usage: {
          inputTokens: 1,
          outputTokens: 1,
          cacheReadInputTokens: 0,
          cacheCreationInputTokens: 0,
        },
        reinvestigateMarker: 1, // simulate a future bug stamping it
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
      reinvestigate: 1,
      concurrency: 1,
    });

    expect(result.analysisCount).toBe(1);
    expect(stub.calls.investigateCalls).toHaveLength(1);
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
