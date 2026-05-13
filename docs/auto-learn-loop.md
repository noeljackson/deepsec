# The auto-learn loop

deepsec's matchers and prompts can be improved by an autonomous loop
that hill-climbs against a labeled benchmark, gated by statistical
significance and Pareto-style regression checks, with a human escape
valve for changes that can't be made safely.

This page is the one-screen tour. Each component has its own page;
follow the links for depth.

```
                ┌─────────────────────────────────────────┐
                │                                         │
                │  matcher TOMLs ─────► scan ─► candidates│
                │  prompt files            │              │
                │                          ▼              │
                │  fixtures / answer keys ─► process ─► findings
                │            │             (LLM)          │
                │            ▼                            │
                │  scanner-only score     processor score │
                │  bench score / CIs       bench score    │
                │            │                  │         │
                │            └─────► gate ◄─────┘         │
                │                     │                   │
                │            ┌────────┴────────┐          │
                │            │                 │          │
                │            ▼                 ▼          │
                │  human-in-loop          autonomous       │
                │  review CLI             bounded-patch    │
                │  (#15)                  agent (#17)      │
                │            │                 │          │
                │            ▼                 ▼          │
                │  regression cases ◄─── matcher edits ───┘
                │                                         │
                └─────────────────────────────────────────┘
```

## The five layers, in plain English

### 0. Fixtures: vendored or git-pinned

Bench tasks point at source either by vendoring `source/` files or by
pinning a remote repo + SHA in `task.toml`:

```toml
[repo]
url    = "https://github.com/tailscale/tailscale.git"
commit = "abc123…"
```

External-repo tasks are shallow-cloned to a fresh temp dir per scoring
run; the source never lands in the deepsec tree. Lets the bench grow
toward realistic-scale corpora (kubernetes, tailscale, etc.) where the
agent's matcher-narrowing has signal. See [`../bench/README.md`](../bench/README.md)
for the worked example and cross-model labeling layout.

### 1. The harness measures what's currently there

- **Scanner eval** ([`bench/README.md`](../bench/README.md)): runs the
  bundled regex matchers against a corpus of labeled tasks. Each task
  is a small source tree plus `answer.yaml` with planted issues and
  decoys. The scorer emits per-slug precision / recall / FP-FN
  breakdowns.
- **Processor eval** ([`bench/PROCESSOR.md`](../bench/PROCESSOR.md)):
  same idea, one layer up. A frozen `FileRecord` (output of the
  scanner) is paired with a recorded `responses.jsonl` (canned LLM
  output). The mock-replay backend hands the recorded responses back
  on demand, so prompt changes can be scored deterministically without
  burning tokens.
- **Recorder** (`deepsec process --record`): captures a live run into
  the same JSONL format the replay backend consumes. Real-mode runs
  become reproducible fixtures.

### 2. Sampling pins make scores reproducible

`--temperature`, `--top-p`, `--seed` on `process` / `revalidate` /
`triage` are pinned and persisted into `ProcessorConfig.ModelConfig`.
Without this every comparison was chasing sampling lottery winners; with
it, two runs of the same prompt produce identical findings.

### 3. Bootstrap CIs replace "score > best + ε"

`benchsec process-score --repeat N --seed K` runs the processor scorer
N times, aggregates each metric with mean / stddev / 95% bootstrap
percentile CI, and writes `summary-repeated.json`. The companion
`benchsec process-compare a/ b/` bootstraps the difference of means and
tags the verdict (`improved` / `regressed` / `inconclusive`). The
autonomous loop uses this gate so "improvement" requires statistical
distinguishability, not noise.

### 4. The human-in-the-loop review CLI

[`docs/matcher-review.md`](matcher-review.md). `benchsec review --slug X`
shows the human the specific FPs and FNs a slug is producing. `--edit`
opens the matcher TOML in `$EDITOR`, rescores, shows the before/after
delta with the specific FPs that disappeared (or appeared). `--commit`
verifies the improvement still holds and writes a regression case so
the same FP can't come back.

This loop is *the* precursor to autonomy. Every shape the autonomous
agent uses — the FP/FN extractor, the rescore-then-gate flow, the
regression-case format — comes from here.

### 5. The bounded-patch agent

[`docs/bounded-patch-agent.md`](bounded-patch-agent.md). `benchsec
agent` runs the supervised loop above with an LLM in the proposer
seat. One iteration is:

1. Pick a target slug (worst-precision slug by default).
2. Show the model the slug's FPs and FNs.
3. Model returns exactly one structured patch:
   `suppress_patterns` / `require_content` / `file_patterns` /
   `requires.tech` / `needs-engine-feature`.
4. Apply, rescore, run the Pareto gate.
5. Gate accepts iff: target precision/recall didn't drop, no other
   slug's HIGH/CRITICAL recall regressed, candidate count grew within
   budget, no patch silenced a matcher, no patch was a no-op.
6. On accept: append regression cases for resolved FPs, commit, log to
   `AGENT_DECISIONS.md`. On reject: revert the matcher file.

**Dry-run by default.** `--apply` is required to actually write. The
agent refuses to run on a dirty git tree.

### The `needs-engine-feature` escape valve

If a slug's FPs can't be fixed by any of the four allowed TOML edits
(e.g. flask-route fires on every route decorator — distinguishing
"interesting" routes needs dataflow, not regex), the model returns
`needs-engine-feature` with a rationale. That gets logged for human
review instead of forcing a bad patch.

The first real run of the agent against the live LLM (GLM-5.1 via
Z.ai's Coding Plan) returned `needs-engine-feature` for `flask-route`
and `go-http-handler` with precise explanations of why. The escape
valve works.

## Document index

| Layer | Doc |
|---|---|
| Architecture overview | [`architecture.md`](architecture.md) |
| Scanner eval harness | [`../bench/README.md`](../bench/README.md) |
| Processor replay eval | [`../bench/PROCESSOR.md`](../bench/PROCESSOR.md) |
| Writing matchers | [`writing-matchers.md`](writing-matchers.md) |
| Configuration | [`configuration.md`](configuration.md) |
| Human review CLI | [`matcher-review.md`](matcher-review.md) |
| Bounded-patch agent | [`bounded-patch-agent.md`](bounded-patch-agent.md) |
| Bake-off pattern | [`bake-off.md`](bake-off.md) |
| Data layout on disk | [`data-layout.md`](data-layout.md) |
| Getting started | [`getting-started.md`](getting-started.md) |
| FAQ | [`faq.md`](faq.md) |

## Common workflows

**Find vulns in a real project** — `getting-started.md` → `scan` →
`process` → `report`.

**Improve a noisy matcher by hand** — `matcher-review.md` → `benchsec
review --slug X --edit` → accept → commit.

**Run the agent autonomously** — `bounded-patch-agent.md` → `benchsec
agent --slug X` (dry-run) → `benchsec agent --slug X --apply
--max-iterations 1` once you trust it.

**Score a prompt variant against a frozen fixture** — `bench/PROCESSOR.md`
→ record fixture with `deepsec process --record` → edit prompt
(`internal/processor/prompts/core.md`) → `benchsec process-score
--repeat 30 --seed 1` before and after → `benchsec process-compare`.
