# Scanner Benchmark Harness

This directory contains scanner-only evaluation tasks for deepsec. The
scorer calls `scanner.Scan` directly, writes each task to a fresh temp
`core.DataRoot`, reads the emitted `FileRecord.Candidates`, and never
calls the processor or an LLM.

## Running

Score every task:

```bash
go run ./cmd/benchsec score
```

Score one task:

```bash
go run ./cmd/benchsec score ts-vulnerable-app
```

Reports are written to `bench/out/<timestamp>/`:

- `summary.json`
- `by_task.tsv`
- `by_slug.tsv`
- `false_positives.json`
- `false_negatives.json`
- `candidate_explosion.json`

Run matcher-pack linting:

```bash
go run ./cmd/benchsec lint-matchers
```

The linter exits non-zero for error-level findings.

## Processor Replay Scoring

Processor-level fixtures live under `bench/processor-fixtures/` and are
scored with deterministic mock replay:

```bash
go run ./cmd/benchsec process-score
```

The scorer loads frozen `FileRecord` inputs, replays recorded
`InvestigateOutput` batches through `processor.Process`, and writes
reports to `bench/out-processor/<timestamp>/`. See
[`PROCESSOR.md`](./PROCESSOR.md) for the fixture layout, response schema,
manual authoring guide, and the deferred real-recording plan.

## Adding A Task

A task is either **vendored** (source files in the bench tree) or
**externally pinned** (source fetched from a git URL + commit SHA at
scoring time).

Vendored:

```text
bench/tasks/<task-id>/
  source/
  answer.yaml
  task.toml          # optional
```

Externally pinned:

```text
bench/tasks/<task-id>/
  answer.yaml
  task.toml          # required, with a [repo] block
```

The runner shallow-clones the repo to a fresh temp dir per scoring
run, scans it, and removes the clone. Source never lands in the bench
tree, so licensing/IP concerns disappear and the bench grows without
inflating the deepsec repo. Reproducible because the SHA is pinned.

`task.toml` supports:

```toml
matcher_only = ["ssrf"]
matcher_exclude = ["missing-rate-limit"]

# Externally pinned source — fetched per scoring run.
[repo]
url    = "https://github.com/tailscale/tailscale.git"
commit = "abc123def4567890abc123def4567890abc12345"
```

Both `url` and `commit` are required when `[repo]` is present.

Keep tasks small and deliberate. Add decoys for sites that look similar
to the vulnerability but must not be counted as true positives.

## Answer Key Schema

```yaml
issues:
  - id: py-ssrf-001
    file: app.py
    severity: HIGH
    cwe: CWE-918
    vulnSlugs: [ssrf, server-side-request-forgery]
    location:
      startLine: 10
      endLine: 10
      tolerance: 2
    scanner:
      mustEmitCandidate: true
decoys:
  - id: py-ssrf-decoy-static-url
    file: app.py
    line: 27
    forbiddenSlugs: [ssrf]
```

`tolerance` defaults to `3` when omitted. A candidate matches an issue
when the file is equal, its slug is one of `vulnSlugs`, and any candidate
line falls within `[startLine - tolerance, endLine + tolerance]`.

Set `scanner.mustEmitCandidate: false` for issues that should be tracked
but are not honestly detectable by the current regex scanner. Those
issues are reported as scanner-uncovered and excluded from scanner recall
denominators.

## Metrics

- `scanner_recall`: detectable answer-key issues matched by at least one
  candidate.
- `recall_critical`, `recall_high`, `recall_medium`, `recall_low`: recall
  split by answer-key severity.
- `scanner_precision`: candidates that match a detectable issue divided
  by total candidates.
- `scanner_precision_by_slug`: candidate precision split by emitted slug.
- `candidate_count_total`: all scanner candidates.
- `candidate_count_noisy`: candidates from matchers tagged
  `noise_tier = "noisy"`.
- `false_positive_decoy_rate`: decoys flagged divided by total decoys.
- `candidate_density`: candidates per KLOC.
- Per-slug FP/FN counts: emitted in `summary.json` and `by_slug.tsv`.

Multiple candidates near one issue count once for recall. They still
remain visible in candidate and precision reports.

## Linter Checks

`benchsec lint-matchers` scans `internal/scanner/matchers/*.toml` and
reports:

- duplicate `slug` declarations,
- unsupported RE2 syntax: lookaround and `\1`-style backreferences,
- invalid Go regular expressions,
- `noise_tier = "noisy"` matchers with no `requires.*` or
  `require_content` gate,
- empty or overbroad `file_patterns` such as `**/*` with no other gate.
