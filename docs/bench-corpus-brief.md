# Critique: deepsec bench-corpus plan (issue #84)

You're being asked for a sharp outside-the-loop critique of a
strategic plan for the `deepsec` security-scanner project. I want
honest pushback — what's wrong, what's missing, what's
over-engineered, what should be re-ordered. Not validation.

## What deepsec is

Open-source AI-powered SAST tool. Pipeline:

```
matcher TOMLs ─► scan ─► candidates ─► AI process ─► findings
       ▲                                  │
       │      ┌────────────────────┐      ▼
       └──────│ benchsec scorer    │ ◄─ bootstrap-CI evidence
              │ precision agent    │
              │ recall agent       │
              │ skeptic 2nd pass   │
              └────────────────────┘
```

12 languages with bundled matchers + tree-sitter AST grammars. ~100
bundled matchers. AI investigation uses Anthropic / OpenAI /
OpenAI-compatible providers. The `benchsec` harness has
`process-score` with bootstrap CIs and `process-compare` that
already does statistically-gated A/B between runs.

Cleared the v0.1.0 release. 23 PRs landed this week. README + docs
are real.

## Current bench state

`bench/tasks/`:

- `go-vulnerable-cli` (handcrafted, ~6 issues)
- `py-vulnerable-flask`
- `ts-vulnerable-app`
- `auth-flow-real-bugs` (new — minimal repros of two Codex Cyber
  findings on a real codebase; deepsec scored 0/2 yesterday, 2/2
  today after matchers shipped)

Total: ~16 bench issues + decoys across 4 tasks. Tiny.

`benchsec score` runs in seconds. The scorer has been used to gate
precision-agent matcher patches for months. The corpus is the
limiting factor, not the harness.

## The plan (issue #84) being critiqued

Build a labeled bench corpus of 50-100 fixtures over Q3. Sources:

1. OWASP Juice Shop confirmed challenges (~10 tasks). Already
   validated against deepsec; tasks would encode the known answer
   key (Login Admin, Search SQLi, Christmas Special, etc.).

2. Curated Codex Cyber findings on `codewire/platform`
   (~20-30 tasks after filtering intentional-design noise). Already
   have the CSV and a comparison script.

3. CVE-Bench / academic datasets (CVE-Bench, BigVul,
   CWE-Bench-Java) vendored via the existing `[repo]` external
   fixture mechanism (~30 tasks).

4. GitHub Security Advisories with linked patch commits (~10
   tasks/quarter as ongoing).

Each fixture follows `bench/tasks/<id>/` shape:
- `source/` — minimal repro files
- `answer.yaml` — `issues:` + `decoys:`
- Optional `[repo]` task.toml for vendored fixtures

Coverage targets across 12 languages, roughly weighted by typical
vuln density (TS/Python/Go at 10-12 each, mobile/native at 3-6).

Once the corpus exists:
- CI-gate every PR on bench delta (issue #85)
- Use the corpus to A/B prompt variants (#86)
- Drives the recall agent to genuinely improve the matcher pack

## What I want from you

Frank critique. Specifically:

1. **Is 50-100 fixtures the right size?** Or too few for
   statistical reliability of the CI gate? Too many to maintain?
   What's the goldilocks number for the harness we have
   (bootstrap-CI + N-repeat process-score)?

2. **Are the 4 sources right?** What's missing — what would you
   add? What looks like a trap? (My guess: academic CVE datasets
   are often noisy / stale / mis-labeled. Real?)

3. **Is the auth-flow-real-bugs PR #82 shape the right template?**
   Or does encoding minimal-repros mask whole-codebase detection
   problems? Should we instead vendor real repos at SHA via `[repo]`
   and accept the test-runtime cost?

4. **What's the maintenance model?** Once we have 80 tasks, what
   keeps them current? Who reviews when an external scanner's
   labels disagree with the bench's?

5. **Sequencing — should anything come before corpus?** Should we
   ship the CI gate (#85) with the current tiny corpus first, just
   to wire the plumbing, then grow the corpus inside the gate's
   pressure? Or is the corpus genuinely upstream of the gate?

6. **What's the single biggest risk that would make this fail?**
   Not minor caveats — the failure mode that kills the whole
   investment.

Be concrete. If you'd reorganize the plan, write the
reorganization. If you'd kill a source, say which and why. If the
size target is wrong, say what it should be.

Repository at `/home/noel/src/noeljackson/deepsec/` — feel free to
read `CLAUDE.md`, `README.md`, `docs/external-comparison.md`,
`docs/juice-shop-validation.md`, and
`bench/tasks/auth-flow-real-bugs/` for grounding. Don't write
code. ~600 words back.
