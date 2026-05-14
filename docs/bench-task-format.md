# Bench task format

Every directory under `bench/tasks/<id>/` is a labeled benchmark
task. The scorer (`benchsec score`) and the precision/recall agents
read these to measure deepsec's behaviour and drive matcher
improvements.

This doc is the authoritative reference for the task file layout
and the **answer-key provenance discipline** that gates the corpus
from quietly rotting.

## Files

```
bench/tasks/<task-id>/
├── task.toml      # REQUIRED for new tasks. Provenance + label rules.
├── answer.yaml    # REQUIRED. Issues + decoys defining the ground truth.
└── source/        # REQUIRED unless task.toml [repo] is set.
    └── *.{go,ts,py,…}
```

For tasks that scan an upstream repo at a pinned SHA instead of
vendored source, `task.toml` carries a `[repo]` block and `source/`
is omitted.

## `task.toml`

```toml
# REQUIRED. Where this task's labels came from.
[provenance]
source          = "handcraft"      # bucket — see below
source_url      = "https://…"      # required when source != "handcraft"
upstream_commit = "abc123…"        # SHA the repro is derived from
                                   # (optional, but required if you
                                   #  reference a real-world repo)
added_at        = "2026-05-14"     # YYYY-MM-DD task created
reviewer        = "@noeljackson"   # GitHub handle of label-truth owner
review_due      = "2026-08-14"     # YYYY-MM-DD label needs revalidation

# REQUIRED. How answer.yaml changes are governed.
[labels]
change_rule = "external-disagreement-opens-issue"
# one of:
#   external-disagreement-opens-issue (default for real-world-derived)
#   auto-update                       (rare; experimental tasks)
#   freeze                            (canonical known-vuln tasks,
#                                       Juice Shop challenges, etc.)

# OPTIONAL. Vendored real-repo source. Mutually exclusive with source/.
[repo]
url    = "https://github.com/example/foo"
commit = "deadbeef…"
```

### `source` buckets

| Value             | Meaning                                                   |
|-------------------|-----------------------------------------------------------|
| `handcraft`       | Author-written minimal repro. Treat as test code.         |
| `juice-shop`      | OWASP Juice Shop confirmed challenge.                     |
| `ghsa`            | GitHub Security Advisory with linked patch commit.        |
| `codex-cyber`     | Curated finding from a Codex Cyber scan.                  |
| `cve-bench-pilot` | One of the 5-task audited pilot from BigVul / CVE-Bench.  |

New sources are accepted but should be added to this list in the
same PR introducing them.

### Review cadence

`review_due` defaults to **+3 months** from `added_at`. The
`benchsec stale` subcommand reports tasks past their due date so
the reviewer can revalidate or extend.

```bash
benchsec stale
# task                                     reviewer         due          overdue
# bench/tasks/some-old-task                @owner           2025-02-01   473d
```

The advisory CI gate (issue #85) calls `benchsec stale` weekly and
opens a label-debt report issue if anything's past due.

## Disagreement protocol

When an external scanner (Codex Cyber, Mythos, etc.) labels a
finding that deepsec also evaluated and the labels conflict:

1. **Do not edit `answer.yaml` directly.**
2. Open a review issue titled `bench: label disagreement —
   <task-id> — <vuln>` with:
   - source excerpt covering the disputed lines
   - exploit argument (or absence)
   - patch link if any
   - why the finding is or is not in scope for deepsec
3. The task's `reviewer` (from `task.toml`) adjudicates.
4. The PR that changes `answer.yaml` cites the review issue.

`labels.change_rule = freeze` overrides this: frozen tasks never
change without an explicit reviewer-authored PR.

## Backwards compatibility

Tasks without a `task.toml` still score correctly (the scorer
treats missing provenance as legacy). New tasks added without
provenance are reviewer's discretion — but issue #90 specifies the
direction is toward universal coverage.

## Validation

`benchsec score` invokes `loadTaskConfig` which validates:

- `[provenance]` block requires `source`, `added_at`, `reviewer`,
  `review_due`.
- Non-`handcraft` sources must declare `source_url`.
- Dates must be `YYYY-MM-DD`.
- `[labels].change_rule` must be one of the documented values.

A `task.toml` that fails validation rejects the whole scoring run
loudly.
