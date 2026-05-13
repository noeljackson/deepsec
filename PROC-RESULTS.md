# Processor Fixture Replay Results

- Branch: `proc/fixtures-B`
- Output run: `bench/out-processor/20260512T220355Z`
- Net LOC delta: `+1147` lines

## Fixture Layout

Fixtures live under `bench/processor-fixtures/<task-id>/` with:

- `source/` for the project root used by `processor.Process`
- `files/` with one pending `core.FileRecord` JSON per file
- `responses.jsonl` with replayed batch outputs in dispatch order
- `answer.yaml` with finding-level labels and optional refusal/finding guards

I kept file records as normal `core.FileRecord` JSON so the scorer can load
them through `core.DataRoot.WriteFileRecord` without an adapter schema. The
fixture filenames replace slashes for readability, while the JSON `filePath`
keeps the real project-relative path.

## responses.jsonl Schema

Each line is:

```json
{"batchPaths":["src/fetch.ts"],"output":{"results":[{"filePath":"src/fetch.ts","findings":[]}],"usage":{"inputTokens":0,"outputTokens":0},"durationMs":0,"numTurns":1,"costUsd":0}}
```

`batchPaths` must exactly match the next `InvestigateBatch` file paths.
`output` is the `processor.InvestigateOutput` wire shape.

## MockReplayBackend

Location: `internal/processor/mockbackend`.

The backend loads `responses.jsonl` at construction, advances one response per
`Investigate` call, errors clearly on mismatch or exhaustion, and forces replay
cost to zero. `Revalidate` and `Triage` satisfy the interface but return
unsupported errors because this scorer only exercises investigation.

## Metrics

`go run ./cmd/benchsec process-score` produced:

```json
{
  "generated_at": "20260512T220355Z",
  "task_count": 2,
  "processor_precision": 1,
  "processor_recall_given_candidate": 1,
  "processor_recall": 1,
  "severity_accuracy": 1,
  "refusal_rate": 0.5,
  "false_positive_count": 0,
  "false_negative_count": 0,
  "per_slug_precision": {
    "ssrf": 1
  },
  "per_slug_recall": {
    "ssrf": 1
  },
  "output_dir": "bench/out-processor/20260512T220355Z"
}
```

## Deferred

- Real backend scoring and token-spending eval runs.
- Recorder implementation for `deepsec process --record ...`.
- Prompt-variant repeated-run scoring and confidence intervals.
- Revalidate/triage replay scoring.

## Notes

The refusal path records as `StatusError` with no produced finding, so the
refusal fixture contributes to `refusal_rate` but not precision or recall
denominators. Repo-wide `go test ./...` still hits the known CLI E2E
permission failures in this environment; the touched packages are green.
