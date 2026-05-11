# Data layout

`data/` is `deepsec`'s on-disk state. Each project owns a subdirectory.
The format is wire-compatible with the original TypeScript implementation
— same field casing, same nesting — so you can switch between the two
on the same directory if you ever need to.

```
data/<projectId>/
├── project.json
├── tech.json                       # detected framework / language tags
├── files/<relative/path>.json      # one FileRecord per source file
├── runs/<runId>.json               # one RunMeta per scan/process/revalidate
└── reports/
    ├── report.md
    ├── report.json
    └── report.csv
```

## FileRecord

Append-only per-file accumulator. Fields (camelCase on disk):

| Field             | Meaning |
|-------------------|---------|
| `filePath`        | Project-relative path (forward slashes). |
| `projectId`       | Owning project id. |
| `candidates[]`    | Scanner-emitted regex hits: `vulnSlug`, `lineNumbers[]`, `snippet`, `matchedPattern`. |
| `lastScannedAt`   | ISO timestamp of the last scan that touched this file. |
| `lastScannedRunId`| RunId of that scan. |
| `fileHash`        | SHA-256 hex of file contents. |
| `findings[]`      | Real findings produced by the AI processor. |
| `analysisHistory[]` | Append-only log of investigations (cost, tokens, agent, refusal, …). |
| `gitInfo`         | Recent committers + ownership (optional, populated by `enrich`). |
| `status`          | `pending` \| `processing` \| `analyzed` \| `error`. |
| `lockedByRunId`, `lockedAt` | Set when a `process` run claims the file. |

## RunMeta

One per CLI invocation that does write-work.

| Field            | Meaning |
|------------------|---------|
| `runId`          | `YYYYMMDDHHMMSS-<4hex>`. |
| `type`           | `scan` / `process` / `revalidate`. |
| `phase`          | `running` / `done` / `error`. |
| `scannerConfig`  | Set for `scan`: which matchers ran, mode (full vs files). |
| `processorConfig`| Set for `process` / `revalidate`: agent type, model, invocation mode, source label. |
| `stats`          | filesScanned, candidatesFound, totalCostUsd, totalInputTokens, totalOutputTokens, totalDurationMs, etc. |

## Versioning the data dir

You typically commit `data/` so PR-time scans can compare against the
baseline. `deepsec data-commit` runs `git add data/ && git commit` for
you with a default message.
