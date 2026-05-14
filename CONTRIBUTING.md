# Contributing to deepsec

The most useful contributions are **new matchers**, **new bench
tasks**, and **scan writeups against public OSS repos**. Each has a
dedicated guide; pointers below.

## Repo layout

```
cmd/
  deepsec/                 The CLI binary
  benchsec/                Benchmark harness binary
internal/
  core/                    Types, paths, schemas, JSON persistence
  scanner/                 File walker, tech detection, TOML matcher engine
    matchers/              Embedded bundled matcher pack (*.toml)
    ast/                   tree-sitter via wazero (AST matching)
  processor/               AI pipeline (AgentBackend + Anthropic / OpenAI backends)
    providers/             Provider registry; profiles.toml is embedded
    prompts/               Embedded system prompts (core.md, agent.md, etc.)
  cli/
    commands/              Each subcommand in its own file
bench/
  tasks/                   Labeled benchmark tasks (see docs/bench-task-format.md)
  baseline.json            Whole-bench score on main (advisory gate compares against this)
docs/                      User-facing docs (see docs/index.md)
fixtures/vulnerable-app/   Planted-vulnerability fixture for tests
```

## Dev loop

```bash
go build ./...                  # build CLIs
go test ./... -race -count=1    # full test suite
go vet ./...                    # static analysis
gofmt -l .                      # format check
staticcheck ./...               # third-party static check
```

The five-step pre-push gate above is what CI splits into the `test`
and `security` jobs. All five must pass.

If you're touching the scanner / matcher pack, also run:

```bash
benchsec score                  # whole-bench recall + precision + decoy-FP rate
benchsec stale                  # label-debt report
```

These are the same numbers the **advisory** `bench` CI job will print
on your PR. The advisory job doesn't block merge but signals a review.

## Sanity-check your setup

Before opening a PR, run:

```bash
deepsec doctor                  # config, providers, matchers, AST grammars
deepsec doctor --project-id <id> --verbose  # add a project context
```

If anything is ⚠ or ✗, see [docs/troubleshooting.md](docs/troubleshooting.md).

## Adding a matcher

Short version (full guide:
[docs/writing-matchers.md](docs/writing-matchers.md), AST variant in
[docs/writing-ast-matchers.md](docs/writing-ast-matchers.md)):

1. Pick a TOML file under `internal/scanner/matchers/*.toml` (or add a
   new one) and append a `[[matcher]]` block with `slug`,
   `description`, `noise_tier`, `file_patterns`, `patterns`, optional
   `require_content` / `requires.tech` / `suppress_patterns`.
2. For structural matching: add an `[[matcher.ast_patterns]]` block
   with a tree-sitter S-expression query against the grammars deepsec
   bundles (12 languages — see `internal/scanner/ast/grammars.go`).
3. Build a bench task in `bench/tasks/<slug>-…/` with a vulnerable
   and a safe variant. See [docs/bench-task-format.md](docs/bench-task-format.md).
4. `benchsec score <task-id>` must show **1.0 recall on the
   vulnerable variant, 0 decoy FPs on the safe variant**.
5. `benchsec score` over the whole corpus must not regress (no new
   FNs in other slugs, no new FPs).

Matchers that only make sense in one organization's codebase go in a
user-supplied TOML referenced from `[matchers].extra_paths` in
`deepsec.config.toml`, not the bundled pack.

## Adding a bench task

See [docs/bench-task-format.md](docs/bench-task-format.md). Every
task must carry `[provenance]` (source, reviewer, review_due) and
`[labels].change_rule` per the task-metadata discipline. Tasks
without provenance are rejected at score time.

## Writing a scan against a public OSS repo

Pick a popular repo. Clone at a recent SHA. Add it to
`deepsec.config.toml`. Run scan + process with `--skeptic`. Write up
findings under `docs/scans/<date>-<repo>.md` following the template in
[docs/scans/2026-05-14-first-batch.md](docs/scans/2026-05-14-first-batch.md).

This produces evidence about what deepsec catches and what it misses
on real code. Findings that the team judges promotable go into
`bench/tasks/` per the corpus protocol (#84).

## Refreshing AST grammars

See [docs/refreshing-grammars.md](docs/refreshing-grammars.md).
Grammar refreshes need Docker (the `emscripten/emsdk` image), aren't
done in CI, and require human review of the WASM diff.

## Style

- Default to **no comments**. Write a comment only when the WHY is
  non-obvious — a hidden constraint, a subtle invariant, a workaround
  for a specific bug.
- Don't reference the current task, fix, or PR in code comments — they
  rot.
- Use the `Edit` tool's pattern: small focused diffs over wholesale
  rewrites.
- Don't add error handling for cases that can't happen. Trust internal
  callers. Validate at system boundaries (user input, external APIs).

## Commit and PR

- Branch off `main`, never push to it directly.
- One logical change per PR. Bug fix doesn't need surrounding cleanup.
- Pre-push gate green; the CI test + security jobs are the canonical
  blockers.
- The `bench` job is advisory — a ❌ doesn't block merge but warrants
  review. See [docs/bench-task-format.md](docs/bench-task-format.md)
  for what triggers it.
- For destructive operations (force-push, history rewrite, mass
  delete), pause and ask in the PR description first.
- Sign commits if your local git is configured to. Don't fight
  `commit.gpgsign=false` if your signing setup is flaky; the project
  doesn't require signatures.

## Reporting security issues

Don't open public issues for vulnerabilities **in deepsec itself**.
See [SECURITY.md](SECURITY.md) for the responsible-disclosure channel.

## Origin

deepsec started as a Vercel-internal TypeScript prototype and was
rewritten in Go for distribution as a single static binary. The
original TypeScript is preserved in git history (commits before
`claude/rewrite-deepsec-go`); the Go rewrite is the canonical
codebase.
