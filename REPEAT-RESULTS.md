# Repeat Scoring Results

## Branch

`repeat/scoring-B`

## Subcommand layout

I kept repeated scoring under the existing command:

```bash
benchsec process-score --repeat N --seed K
```

That preserves single-run behavior for `process-score` and makes repeat
mode an additive option on the scorer it extends. I added a separate
comparison subcommand:

```bash
benchsec process-compare <baseline-dir> <candidate-dir>
```

The comparison is a distinct operation over two completed repeated-run
directories, so a separate subcommand keeps the CLI shape clearer.

## Stochastic fixture schema

The stochastic backend autodetects JSONL lines with `alternatives`:

```json
{"batchPaths":["src/fetch.ts"],"alternatives":[{"weight":0.5,"output":{"results":[...]}},{"weight":0.5,"output":{"results":[]}}]}
```

`batchPaths` must exactly match the next processor batch. Each
alternative has a positive `weight` and a normal
`processor.InvestigateOutput` in `output`. The fixture lives at
`bench/processor-stochastic-fixtures/ssrf-stochastic/` so default
deterministic processor fixtures stay unchanged.

## Bootstrap notes

Each metric uses the per-repeat scalar samples. The estimator is the
mean, and `ci_low` / `ci_high` are the 2.5th and 97.5th percentiles of
bootstrap-resampled means. The default is 1000 resamples. Bootstrap RNG
uses `math/rand/v2` PCG with deterministic metric-specific seeds derived
from the CLI seed; no parallelism is used.

`stddev` is sample standard deviation. `median` is computed from sorted
raw samples. JSON stores at most the first 100 raw samples per metric.

## Deterministic example

Command:

```bash
go run ./cmd/benchsec process-score --repeat 5 --seed 1 --out /tmp/deepsec-repeat-det
```

Excerpt from `summary-repeated.json`:

```json
{
  "generated_at": "20260513T093846Z",
  "repeat": 5,
  "seed": 1,
  "bootstrap_samples": 1000,
  "metrics": {
    "processor_precision": {
      "mean": 1,
      "stddev": 0,
      "median": 1,
      "ci_low": 1,
      "ci_high": 1,
      "samples": [1, 1, 1, 1, 1]
    },
    "processor_recall": {
      "mean": 1,
      "stddev": 0,
      "median": 1,
      "ci_low": 1,
      "ci_high": 1,
      "samples": [1, 1, 1, 1, 1]
    },
    "refusal_rate": {
      "mean": 0.5,
      "stddev": 0,
      "median": 0.5,
      "ci_low": 0.5,
      "ci_high": 0.5,
      "samples": [0.5, 0.5, 0.5, 0.5, 0.5]
    }
  }
}
```

The deterministic replay fixtures have zero variance, so each CI is a
point interval.

## Stochastic example

Command:

```bash
go run ./cmd/benchsec process-score --tasks bench/processor-stochastic-fixtures --repeat 30 --seed 1 --out /tmp/deepsec-repeat-stoch
```

Excerpt from `summary-repeated.json`:

```json
{
  "generated_at": "20260513T093846Z",
  "repeat": 30,
  "seed": 1,
  "bootstrap_samples": 1000,
  "metrics": {
    "processor_recall": {
      "mean": 0.6333333333333333,
      "stddev": 0.4901325178535609,
      "median": 1,
      "ci_low": 0.43333333333333335,
      "ci_high": 0.8,
      "samples": [1, 0, 1, 0, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 0, 1, 1, 1, 1, 1, 1, 0, 0, 1, 1, 0, 1, 1, 0, 0]
    },
    "false_negative_count": {
      "mean": 0.36666666666666664,
      "stddev": 0.4901325178535608,
      "median": 0,
      "ci_low": 0.2,
      "ci_high": 0.5666666666666667,
      "samples": [0, 1, 0, 1, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 1, 0, 0, 0, 0, 0, 0, 1, 1, 0, 0, 1, 0, 0, 1, 1]
    }
  }
}
```

The stochastic fixture alternates between reporting the expected SSRF and
returning no finding, so recall and false-negative count have non-zero CI
width.

## Compare example

Synthetic repeated summaries:

- baseline `processor_precision` samples: `[0.45, 0.46, 0.47, 0.48, 0.49]`
- candidate `processor_precision` samples: `[0.80, 0.81, 0.82, 0.83, 0.84]`

Command:

```bash
go run ./cmd/benchsec process-compare /tmp/deepsec-compare-a /tmp/deepsec-compare-b
```

Output:

```text
metric	mean_a	mean_b	diff	ci_low	ci_high	direction	verdict
processor_precision	0.470000	0.820000	0.350000	0.332000	0.366000	higher	improved
```

## Net LOC delta

Implementation delta before this results file: `+840/-10`, net `+830`.

## What surprised me

The existing processor scorer was already cleanly factored around a
single task scorer, so repeat mode did not need to duplicate matching
logic. The main subtlety was keeping the stochastic fixture out of the
default deterministic fixture directory; otherwise the default
`process-score --repeat` path would no longer demonstrate point
intervals on the starter fixtures.
