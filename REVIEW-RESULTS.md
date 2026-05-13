# Review Results

Branch: `review/cli-B`

## Subcommand Layout

I added one `benchsec review` command with mutually exclusive mode flags:

- default: readable FP/FN report for `--slug`
- `--edit`: open the bundled matcher TOML, rescore, and accept/discard/edit again
- `--commit <message>`: verify an accepted edit still improves, add a regression case, stage, and commit
- `--emit-fps`, `--emit-fns`, `--rescore`: non-interactive script surfaces

One command keeps the supervised workflow discoverable while giving future automation small JSON-producing flags.

## Regression Case Format

Cases are stored in `internal/scanner/regression_cases.toml` as `[[case]]` entries. The loader/test lives in `internal/scanner/regressions/` and runs each case against the named bundled matcher with `must_fire` or `must_not_fire`.

## Sample `--emit-fps`

```json
[]
```

Command used:

```bash
go run ./cmd/benchsec review --slug ssrf --emit-fps --out /tmp/deepsec-review-out
```

## Sample `--edit` Delta

No-op edit using `EDITOR=true`:

```text
Old: precision 1.00, recall 1.00, FP count 0, FN count 0
New: precision 1.00, recall 1.00, FP count 0, FN count 0
False positives disappeared (0):
  none
New false positives (0):
  none
False negatives resolved (0):
  none
New false negatives (0):
  none
No metric delta; nothing to accept.
```

## Net LOC Delta

Implementation delta before this report file: `+949 / -8` lines, net `+941`.

## Another Hour

I would make `--commit` capture more than one regression case when a single accepted edit resolves multiple FPs/FNs, with an interactive selector for which cases to preserve.
