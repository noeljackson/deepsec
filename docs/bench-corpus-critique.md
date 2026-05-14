# Outside-loop critique: bench-corpus plan (codex GPT-5.5)

Captured 2026-05-14 from a one-shot `cw exec local codex app-server`
session evaluating the plan in issue #84. The brief is at
`docs/bench-corpus-brief.md` (also in this PR). The reviewer was given
read access to CLAUDE.md, README.md, docs/external-comparison.md,
docs/juice-shop-validation.md, bench/tasks/auth-flow-real-bugs/,
bench/score.go, bench/agent.go, bench/recall_agent.go.

This critique reordered the plan substantially. The TL;DR is at the
bottom. Verbatim below.

---

## 1. Size

50-100 fixtures is the wrong headline metric. The unit that matters is
labeled issue/decoy pairs per vulnerability family and language, not
fixture count. An 80-task corpus with one obvious issue each will
still give false confidence, especially for process-score where LLM
variance dominates small denominators. For CI gating, target roughly
200-300 labeled issues and at least the same number of decoys, with
3-5 independently shaped examples per important slug. That probably
means 60-80 fixtures if they are dense and well-designed. Start the
gate as advisory once you hit about 100 issues / 100 decoys; make it
blocking only after it has enough history to prove it does not flap.
N-repeat helps estimate processor variance, but it does not fix
systematic label bias or missing strata.

## 2. Sources

Juice Shop is useful but dangerous: it is mostly a TypeScript/Node
teaching app with intentionally theatrical bugs. Use it for end-to-end
sanity, not as a large slice of the corpus. The curated Codex Cyber
findings are the best source if they are aggressively triaged; they
represent real scanner gaps and real code. GitHub Security Advisories
with patch commits are also strong, but only when the vulnerable line
and exploit shape are reviewable without reconstructing an entire
incident from a giant diff. Academic datasets are the trap. BigVul-
style corpora are often stale, noisy, patch-derived in misleading
ways, and biased toward C/C++ commit patterns. Do not vendor 30
academic tasks by default. Put them behind a probation process:
import 5, manually audit labels, measure scanner usefulness, then
decide. Missing source: real negative corpora. You need clean
production repos or clean files labeled "no issue" to pressure
precision, not just vulnerable snippets with local decoys.

## 3. Fixture shape

The auth-flow-real-bugs template is good for matcher development but
insufficient as the main benchmark shape. Minimal repros preserve the
vulnerability mechanic and make review cheap, but they erase whole-
codebase problems: framework routing, config-driven auth boundaries,
generated code, call chains across packages, and noisy neighboring
patterns. Use a two-tier corpus. Tier 1 is minimal repros for fast PR
gating and matcher regression. Tier 2 is vendored real repos at fixed
SHA for nightly or pre-merge advisory scoring. Do not accept full
runtime cost in every PR; do accept it somewhere, or the benchmark
will train deepsec to solve benchmark-shaped toy code.

## 4. Maintenance

The plan currently lacks ownership. Every task needs provenance, label
reviewer, date added, source SHA, expected vuln semantics, and a rule
for label changes. Treat answer.yaml as test code requiring security
review, not as inert data. When another scanner disagrees, the bench
should not auto-move; disagreement opens a review issue with
evidence: source excerpt, exploit argument, patch link if any, and
why the finding is or is not in scope for deepsec. Add "label debt"
tracking and periodic pruning. If nobody owns stale labels, 80 tasks
will quietly become a junk drawer.

## 5. Sequencing

Ship the CI gate plumbing now, but advisory-only and explicitly non-
authoritative. Use the current tiny corpus to prove reports, diffs,
thresholds, caching, and developer ergonomics. Then grow the corpus
under that feedback loop. Blocking CI before corpus maturity is
backwards; delaying all gate work until the corpus is perfect is also
wrong. Sequence should be: advisory gate, corpus schema/provenance
hardening, first 20 high-quality tasks, flake-rate tracking, then
blocking thresholds on stable scanner-only metrics. Processor A/B
gates come later because LLM repeat cost and variance will otherwise
dominate the project.

## 6. Biggest risk

The killer failure mode is Goodharting: building a benchmark that is
easy to improve and hard to trust. Minimal repros, Juice Shop
challenges, and handpicked external findings can turn into a private
leaderboard for matcher patches rather than a representative measure
of user security value. Once agents optimize against that corpus, any
label noise, source skew, or toy-code bias gets amplified. The fix is
not "more tasks"; it is stratification, negative corpora, held-out
real-repo tasks, label review discipline, and a hard separation
between fast regression fixtures and slower realism fixtures.

## Reorganised plan

First formalize task metadata and label review rules. Second wire
advisory CI immediately. Third build 20-30 high-confidence tasks from
curated Codex findings, GSAs, and a small audited academic pilot,
with equal decoy pressure. Fourth add a nightly real-repo tier. Fifth
expand toward 200-300 labeled issues only where coverage gaps are
explicit, especially Java/Rust/PHP/C#/C/C++/Swift/Kotlin, instead of
letting TypeScript/Python/Go absorb the benchmark because they are
easiest.

---

## Impact on filed issues

Concrete actions taken in response (this same PR or follow-up):

- #85 (CI gate) is **resequenced ahead of #84**. Gate ships advisory
  with current 4 tasks first; growth comes after.
- #84 (corpus) is rewritten:
  - target metric: labeled issue/decoy pairs per family×language,
    not fixture count
  - new requirement: negative corpora (clean files)
  - two tiers: minimal repros (Tier 1) + vendored repos at SHA
    (Tier 2)
  - academic datasets dropped to 5-task audited pilot
  - task metadata schema added (provenance, label reviewer, date,
    source SHA, label-change rule)
- New issue (filed alongside this PR): "Task metadata + label review
  discipline" — answer.yaml provenance, review process, label-debt
  tracking. This is upstream of any new task being added.
