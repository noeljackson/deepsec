# Operational tooling

deepsec ships with a small set of diagnostic + reporting commands aimed
at the day-to-day operator: people running deepsec on CI, paying the
bill, or trying to figure out why a scan came back empty.

## `deepsec doctor`

Diagnose a deepsec setup. Run this first when something looks wrong —
its output maps directly to entries in
[`troubleshooting.md`](troubleshooting.md).

```
deepsec doctor                        # check config / providers / matchers / AST
deepsec doctor --project-id myproj    # add a project-level view
deepsec doctor --verbose              # list every matcher + skipped slug
```

Exit code 0 on all-✓, non-zero on ✗.

## `deepsec spend`

Aggregate AI cost across runs. Reader-only — uses each project's
existing `AnalysisHistory` cost data; no new tracking required.

```
deepsec spend                                 # last 30d, all projects, by agent
deepsec spend --project-id myproj --since 7d
deepsec spend --by slug --since 2026-04-01
deepsec spend --by phase --format json
```

### Flags

| Flag | Default | Notes |
|------|---------|-------|
| `--project-id` | (all projects) | If empty, walks every project under the data root |
| `--since` | `30d` | Accepts `Nd`, Go durations (`24h`, `90m`), `YYYY-MM-DD`, or `all` |
| `--by` | `agent` | `agent`, `phase`, `slug`, or `file` |
| `--format` | `text` | `text`, `json`, or `csv` |

### Dimensions

- **agent** — by provider (`anthropic`, `openai`, `zai-coding`, …).
  Flat-rate providers like `zai-coding` show $0; that is correct (the
  cost is not pulled from the provider's API).
- **phase** — by pipeline phase: `process`, `skeptic`, `revalidate`,
  `triage`, …
- **slug** — by vulnerability slug. Each investigation's cost is split
  equally across the distinct slugs of findings produced by that run
  for that file. Investigations that produced no findings land in the
  `(no findings)` bucket.
- **file** — by file path. Useful for finding hotspots ("which file
  takes the most reinvestigations?").

### Sample output

```
$ deepsec spend --project-id myproj --since 30d

Period:      2026-04-14 → 2026-05-14
Runs:        142
Entries:     1,820
Total cost:  $18.43

by agent:
  anthropic                                    $  14.20   77.0%
  zai-coding                                   $   4.23   23.0%
```

`--format json` returns:

```json
{
  "period": "2026-04-14 → 2026-05-14",
  "total": 18.43,
  "runs": 142,
  "entries": 1820,
  "dimension": "agent",
  "rows": [
    {"key": "anthropic",  "usd": 14.20, "pct": 77.0},
    {"key": "zai-coding", "usd":  4.23, "pct": 23.0}
  ]
}
```

CSV is the same row set in `key,usd,pct` columns — convenient for
piping into a spreadsheet or BI tool.

### What `deepsec spend` does not do (yet)

- **Enforce a budget.** `--max-cost-usd` enforces per-run; this is
  read-only across runs. A future `deepsec budget --weekly 5.00`
  enforcement layer is tracked as a follow-up to #96.
- **Pull from the provider's billing API.** Costs come from each
  agent's own `costUsd` field on the AnalysisHistory entry, which the
  backend populates from response headers. Flat-rate providers report
  $0.

## See also

- [`troubleshooting.md`](troubleshooting.md) — diagnostic table for
  `deepsec doctor` output.
- [`ci-integration.md`](ci-integration.md) — using `--fail-on` and
  `deepsec pr-comment` in CI.
- [`compliance-reporting.md`](compliance-reporting.md) — SOC2 / SSDF
  signed manifests.
