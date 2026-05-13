# Matcher Review Loop

`benchsec review` is the supervised loop for improving scanner matchers.
It works one matcher slug at a time so a human can inspect the scorer's
specific false positives and false negatives before changing TOML.

## Read A Slug Report

```bash
go run ./cmd/benchsec review --slug ssrf
```

The command runs the scanner scorer over `bench/tasks`, filters the
per-slug results, and prints the slug's precision, recall, false
positives, and false negatives. Use this before editing so the matcher
failure mode is visible without opening the JSON reports.

Machine-readable forms are available for scripts:

```bash
go run ./cmd/benchsec review --slug ssrf --emit-fps
go run ./cmd/benchsec review --slug ssrf --emit-fns
go run ./cmd/benchsec review --slug ssrf --rescore
```

`--emit-fps` and `--emit-fns` print JSON only. Future automation can use
those lists as a stable input surface while leaving the interactive
review path plain and human-readable.

## Edit A Bundled Matcher

```bash
go run ./cmd/benchsec review --slug ssrf --edit
```

`--edit` locates the bundled TOML file under
`internal/scanner/matchers/`, records the current slug metrics, opens
the file in `$EDITOR` (or `vi`), then recompiles and rescores after the
editor exits. The delta shows the old and new precision, recall, false
positive count, and false negative count, plus the specific cases that
appeared or disappeared.

After each edit, choose:

- `a` to accept the matcher file as it is and record the baseline needed
  by `--commit`.
- `d` to discard the edit and restore the pre-edit TOML.
- `e` to reopen the editor and try again.

Use `--edit` for changes intended to land in the bundled matcher pack.
For project-specific rules or experimental matcher packs, keep authoring
external TOML files and load them through the normal `matchers.extra_paths`
configuration instead; those should not be committed into the bundled
pack until they are broadly useful.

## Commit An Accepted Edit

```bash
go run ./cmd/benchsec review --slug ssrf --commit "Narrow ssrf matcher"
```

`--commit` requires a prior accepted `--edit` for the same slug. It
rescans the fixtures, verifies the slug still improves against that
recorded baseline, appends one regression case for a resolved false
positive or false negative, stages the matcher TOML and regression
corpus, and creates a git commit on the current branch. It never pushes.

## Regression Cases

Regression cases live in:

```text
internal/scanner/regression_cases.toml
```

Each case runs one named matcher against inline content:

```toml
[[case]]
slug = "ssrf"
expectation = "must_fire" # or "must_not_fire"
content = "fetch(req.query.target);\n"
file_path = "src/lib/fetch-proxy.ts"
reason = "user-controlled URL flowing into fetch()"
source_ref = "ts-ssrf-001"
added_at = "2026-05-13"
```

`must_fire` protects false-negative fixes. `must_not_fire` protects
false-positive fixes. The regression test loads every case and runs the
named bundled matcher, so future matcher edits fail fast when they undo a
previous supervised fix.
