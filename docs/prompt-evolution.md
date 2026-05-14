# Prompt evolution

The AI investigation prompt (`internal/processor/prompts/core.md`) is
the highest-leverage iteration point on already-scanned candidates.
A 5% precision lift on the core prompt is worth more than 10 new
matchers — every existing scan benefits immediately.

This walkthrough shows the loop deepsec uses to A/B candidate
prompts against the bundled baseline.

## The loop

```
                ┌──────────────────────────────────────┐
                │  1. Edit `core.candidate.md`         │
                │  2. process-score baseline           │
                │  3. process-score candidate          │
                │  4. process-compare baseline vs cand │
                │  5. ship the winner, or iterate      │
                └──────────────────────────────────────┘
```

## 1. Author a candidate

```bash
cp internal/processor/prompts/core.md /tmp/core.candidate.md
$EDITOR /tmp/core.candidate.md
```

The candidate file does not need to live in the repo — it lives
wherever `--core-prompt` can read it.

## 2. Score the baseline

```bash
benchsec process-score --repeat 8 --seed 1 \
  > /tmp/baseline.json
```

`--repeat 8` runs the scoring eight times against the bench corpus
with a stable seed. The repeated runs feed bootstrap-CI intervals
for each metric so we can tell signal from LLM jitter.

## 3. Score the candidate

```bash
benchsec process-score --repeat 8 --seed 1 \
  --core-prompt /tmp/core.candidate.md \
  > /tmp/candidate.json
```

`--core-prompt` swaps the bundled `core.md` for the candidate file.
Everything else — fixtures, slug hints, framework hints, recorded
mock responses — stays identical. Apples vs apples.

## 4. Compare

```bash
benchsec process-compare \
  bench/out-processor/<baseline-timestamp> \
  bench/out-processor/<candidate-timestamp> \
  --threshold 0.02
```

`--threshold 0.02` ignores deltas where the bootstrap CI of the
candidate doesn't exclude the baseline's by at least 2 percentage
points. Anything below that is noise.

The verdict column reports per-metric `improved`, `regressed`, or
`neutral`. **Ship the candidate only if at least one metric
improves and none regresses past the threshold.**

## 5. Ship or iterate

If the candidate wins:

```bash
cp /tmp/core.candidate.md internal/processor/prompts/core.md
git add internal/processor/prompts/core.md
git commit -m "prompts: lift core precision from X% to Y% (process-compare attached)"
```

Attach the `process-compare` output to the PR description so
reviewers can see the bootstrap CIs.

If the candidate loses or breaks even, iterate: keep tweaking the
candidate, re-score, re-compare. The mock-replay backend means
each iteration costs cents, not dollars.

## What to vary

Good prompt knobs to A/B:

- **Severity calibration** — is "HIGH" actually rare or are we
  HIGH-spammy?
- **Refusal language** — when to decline ("can't tell from this
  file alone") vs. push through.
- **Slug-specific framing** — do we want the agent to be more
  skeptical on `command-injection` than on `weak-crypto`?
- **Confidence reasoning** — make the model say *why* a finding is
  high-confidence; downstream code uses `confidence` to gate
  reporting.

What **not** to vary:

- The JSON output schema (downstream code depends on it; changes
  there are wire-shape breaks, separate concern).
- Bench fixture content (changing fixtures changes the benchmark,
  not the prompt).

## Notes on variance

LLM output is stochastic. With `--repeat 8 --seed 1`, the
bootstrap CI typically falls to ±0.02 on precision and ±0.03 on
recall for a 20-task corpus. Smaller corpora or fewer repeats
inflate the noise floor; bigger ones tighten it. For real prompt
changes you want CIs around ±0.01 — set `--repeat 16` if the
bench corpus is large enough to make that affordable.

The default `--bootstrap-samples 1000` is fine for most cases;
bump to 5000 if a verdict sits right on the threshold and you
want a tighter confidence band.

## Beyond `core.md`

Other prompts (`skeptic.md`, `agent.md`, `patcher.md`,
`recall_agent.md`) follow the same shape. As of v0.2 only
`--core-prompt` is wired; sibling flags are
straightforward additions when those prompts become the focus.
File an issue first.

## See also

- [`bench-task-format.md`](bench-task-format.md) — what the
  corpus task format looks like
- [`auto-learn-loop.md`](auto-learn-loop.md) — the full
  self-improving loop, of which prompt-evolution is one knob
- [`bake-off.md`](bake-off.md) — multi-codex prompt bake-off
  pattern used for substantial prompt rewrites
