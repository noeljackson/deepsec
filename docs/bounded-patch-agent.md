# Bounded Patch Agent

`benchsec review` is the supervised loop: it shows one matcher slug's
false positives and false negatives, lets a human edit TOML, then
rescans before committing an accepted edit.

`benchsec agent` is the autonomous loop. It chooses one slug, asks a
proposer for exactly one bounded TOML patch, scores the patch against
the scanner bench, and accepts it only when the gate passes.

## Safety Rails

- Dry-run is the default. Use `--apply` before the agent writes matcher
  TOML, appends regression cases, or commits.
- `--max-iterations` limits accepted patches per invocation. Start with
  `--max-iterations 1 --apply` until you trust it. Then ramp.
- `--max-rejections` halts after repeated failed proposals.
- `--held-out task-a,task-b` removes tasks from proposer context and
  gate scoring, then prints their score delta separately.
- The apply path refuses dirty git trees.
- Only `internal/scanner/matchers/*.toml`,
  `internal/scanner/regression_cases.toml`, and `AGENT_DECISIONS.md`
  are written by the agent.
- The patch validator rejects changes outside `suppress_patterns`,
  `require_content`, `file_patterns`, and `requires.tech`.

## What Gets Logged

Accepted and rejected apply runs append one entry to `AGENT_DECISIONS.md`
with the slug, patch summary, gate result, regression-case count, and
commit note. Rejected runs say why the gate failed and leave no matcher
commit.

## Examples

Dry-run with a deterministic mock proposer:

```bash
go run ./cmd/benchsec agent \
  --slug flask-route \
  --mock-patch '{"decision":"suppress_pattern","suppress_pattern":"(?i)admin_required","rationale":"suppress a known decoy decorator"}'
```

Apply one accepted patch with the default `zai-coding` profile:

```bash
go run ./cmd/benchsec agent --slug flask-route --max-iterations 1 --apply
```

Use a held-out task for a generalization check:

```bash
go run ./cmd/benchsec agent \
  --slug flask-route \
  --held-out py-vulnerable-flask \
  --max-iterations 1
```
