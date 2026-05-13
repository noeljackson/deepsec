# CI integration — diff scanning end-to-end

Most users will adopt deepsec as a PR check, not a full scan. This
walks through the cheap, fast, end-to-end flow:

1. On every PR, scan **only the files changed by the PR**.
2. Investigate just those candidates with a budget-bounded AI backend
   (e.g. the Z.ai coding-plan subscription via `zai-coding`).
3. Surface net-new findings as a PR comment, fail the check on HIGH
   severity.

The same `--diff` flag powers a pre-commit hook for local feedback
before you push.

## 1. Pre-commit hook (local feedback)

If you use [pre-commit](https://pre-commit.com), add deepsec to
`.pre-commit-config.yaml`:

```yaml
repos:
  - repo: https://github.com/noeljackson/deepsec
    rev: <tag-or-sha>
    hooks:
      - id: deepsec-scan-staged
        # Optional: set the project id; defaults to "default"
        # env DEEPSEC_PROJECT_ID=my-project
```

This runs `deepsec scan --diff HEAD` over the files staged for commit
— regex + AST matchers only, no AI calls, ~100ms per file. Use it as
a fast guard against the obvious patterns (secrets, classic SQLi,
`eval(req.body)`, etc.) before the slower CI investigation runs.

The `deepsec-process-diff` hook is the same flow but with the AI
backend — it's `stages: [manual]` (off by default) so you opt in with
`pre-commit run deepsec-process-diff` when you want it.

## 2. GitHub Actions: PR check

```yaml
name: deepsec
on:
  pull_request:
    branches: [main]

permissions:
  contents: read
  pull-requests: write

jobs:
  scan:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with:
          fetch-depth: 0  # needed for `--diff origin/main`

      - name: install deepsec
        run: go install github.com/noeljackson/deepsec/cmd/deepsec@latest

      - name: init project (idempotent)
        run: deepsec init --project-id pr --root .

      - name: scan PR diff
        run: deepsec scan --project-id pr --diff origin/${{ github.base_ref }}

      - name: investigate candidates
        env:
          ZAI_API_KEY: ${{ secrets.ZAI_API_KEY }}
        run: |
          deepsec process \
            --project-id pr \
            --agent zai-coding \
            --diff origin/${{ github.base_ref }} \
            --max-cost-usd 1.50 \
            --fail-on HIGH

      - name: comment on PR
        if: always()
        env:
          GITHUB_TOKEN: ${{ secrets.GITHUB_TOKEN }}
        run: |
          deepsec pr-comment \
            --project-id pr \
            --skip-empty
```

Key bits:

- `actions/checkout@v4` with `fetch-depth: 0` is required for git to
  resolve `origin/<base>`.
- `--agent zai-coding` uses the Z.ai coding-plan subscription —
  effectively flat-rate at usual scan volumes. Drop in `anthropic`,
  `openai`, or any TOML-defined provider profile.
- `--max-cost-usd 1.50` caps spend per PR.
- `--fail-on HIGH` makes `process` exit non-zero when the run
  produces a HIGH or CRITICAL finding (and the finding hasn't been
  cleared as false-positive / fixed by revalidation). The job fails,
  GitHub blocks merge.
- `pr-comment --skip-empty` posts the standard "deepsec found N
  net-new findings" comment only when there's something to report.

## 3. Severity threshold (`--fail-on`)

`--fail-on=<SEVERITY>` accepts `CRITICAL`, `HIGH`, `MEDIUM`, `LOW`. A
finding triggers the failure when:

- its severity meets or exceeds the threshold, **and**
- its revalidation (if any) didn't already mark it as
  `false-positive` or `fixed`.

Findings whose verdict is `uncertain` or absent still count — the
gate is conservative.

If you want a stricter gate, pair `--fail-on` with `--skeptic`: the
skeptic re-reviews each finding, drops the ones it can disprove,
demotes uncertain ones to LOW. After that, `--fail-on HIGH` only
fires on findings the skeptic could not disprove.

```bash
deepsec process \
  --project-id pr \
  --diff origin/main \
  --skeptic \
  --fail-on HIGH
```

## 4. What `--diff` actually scans

`scan --diff <ref>` and `process --diff <ref>` both shell out to:

```
git diff --name-only --diff-filter=ACMR <ref>
```

This includes:

- Files **changed in commits since `<ref>`** (the normal PR set).
- Files **staged or working-tree modified relative to `<ref>`** (the
  pre-commit case).

It excludes deletions (`D`). Untracked files are not picked up — `git
add` them first if you want them scanned in a pre-commit context.

## 5. Reading the output

After process runs, the artefacts live under `data/<project-id>/`:

- `runs/<run-id>.json` — run metadata
- `files/<path>.json` — per-file findings + analysis history
- `reports/report.md|json|csv` — written by `deepsec report`

For human review, generate the [HTML report viewer](./reporting.md):

```bash
deepsec report --project-id pr --format html --output ./site
```

For compliance evidence (SOC2 / SSDF), the same command takes
`--format soc2|ssdf` to produce a signed JSON manifest. See
[compliance-reporting.md](./compliance-reporting.md).
