# Processor Replay Fixtures

Processor fixtures exercise the AI investigation layer without calling a
real model. Each fixture freezes the `FileRecord` inputs and replays the
recorded `InvestigateOutput` batches through `processor.Process`, so
prompt and scoring changes run against deterministic inputs and outputs.

## Layout

```text
bench/processor-fixtures/<task-id>/
  source/               # optional project root used when Process builds batches
  files/                # one JSON FileRecord per pending file
    <relpath-with-slashes-replaced>.json
  responses.jsonl       # one recorded batch response per line, dispatch order
  answer.yaml           # expected processor-level findings
  task.toml             # reserved for future fixture overrides
```

`files/*.json` use the normal `core.FileRecord` wire shape. Records must
have `status: "pending"` and at least one populated candidate. File paths
inside the JSON remain project-relative paths such as `src/fetch.ts`; the
flat filename under `files/` is only for fixture readability.

## Replay Schema

Each `responses.jsonl` line is:

```json
{"batchPaths":["src/fetch.ts"],"output":{"results":[{"filePath":"src/fetch.ts","findings":[]}],"usage":{"inputTokens":0,"outputTokens":0},"durationMs":0,"numTurns":1,"costUsd":0}}
```

`batchPaths` must exactly match the next batch passed to
`MockReplayBackend`. The scorer runs with batch size `1` and concurrency
`1`, so dispatch order is stable. `output` is the
`processor.InvestigateOutput` shape. Replay forces `costUsd` to zero.

`answer.yaml` uses finding-level labels:

```yaml
findings:
  - id: ssrf-tp-001
    file: src/fetch.ts
    vulnSlugs: [ssrf, server-side-request-forgery]
    severity: HIGH
    location: { startLine: 6, endLine: 6, tolerance: 1 }
    processor:
      mustReportFinding: true
expected_refusals: 0
expected_findings_min: 1
```

A produced finding matches an answer entry when file and slug match and
one produced line falls inside the answer location tolerance.

## Running

```bash
go run ./cmd/benchsec process-score
go run ./cmd/benchsec process-score ssrf-true-positive
```

Reports are written to `bench/out-processor/<timestamp>/`:

- `summary.json`
- `by_task.tsv`
- `by_slug.tsv`
- `false_positives.json`
- `false_negatives.json`
- `severity_mismatches.json`

## Adding A Fixture Manually

Create a small source tree under `source/`, then add one pending
`FileRecord` JSON per file under `files/`. Keep candidates narrow and
human-readable. Add one line to `responses.jsonl` per deterministic batch
in file-path order. Finally, curate `answer.yaml` with the findings the
processor should report, including slug aliases and a small line
tolerance.

## Recording a real fixture

`deepsec process --record <path>` captures every Investigate batch into
a JSONL file in dispatch order — the same format the replay scorer
consumes. Workflow:

```bash
# 1. Scan the target project so candidates exist.
deepsec scan --project-id myproj --root /path/to/project

# 2. Process with a real backend AND tee the responses into a fixture.
deepsec process \
  --project-id myproj \
  --agent anthropic \
  --batch-size 1 --concurrency 1 \
  --record bench/processor-fixtures/myproj/responses.jsonl

# 3. Move the relevant FileRecord JSONs into the fixture's files/
#    directory (deepsec writes them under data/<project>/files/).

# 4. Hand-author answer.yaml to label the findings that should be
#    reported when the recorded responses are replayed.
```

The recorder writes only successful Investigate batches. Failed or
quota-exhausted batches are skipped — the replay scorer treats every
line of `responses.jsonl` as a known-good response, and a half-recorded
batch would mismatch on replay. Pin `--batch-size 1 --concurrency 1`
during recording so batches are deterministic; otherwise the recorded
JSONL line ordering can race with the model's per-batch dispatch.

Pair `--record` with `--temperature 0` and `--seed N` (OpenAI-compat
providers) to make the captured run as reproducible as possible.
