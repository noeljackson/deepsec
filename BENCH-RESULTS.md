# Bench Results

Branch: `bench/scanner-eval-A`

## Built

- Added `cmd/benchsec score` for scanner-only scoring against YAML answer keys.
- Added `cmd/benchsec lint-matchers` for bundled matcher-pack checks.
- Added `bench/tasks/ts-vulnerable-app`, `bench/tasks/go-vulnerable-cli`, and `bench/tasks/py-vulnerable-flask`.
- Added `bench/README.md` with task authoring, metric definitions, and linter documentation.

## Scorer Metrics

Latest run: `go run ./cmd/benchsec score`

```json
{"generated_at":"20260512T195728Z","task_count":3,"scanner_recall":0.8571428571428571,"recall_critical":1,"recall_high":0.8571428571428571,"recall_medium":0.75,"recall_low":0,"scanner_precision":0.5217391304347826,"candidate_count_total":23,"candidate_count_noisy":16,"false_positive_decoy_rate":0,"candidate_density":134.50292397660817,"recall_by_severity":{"CRITICAL":1,"HIGH":0.8571428571428571,"LOW":0,"MEDIUM":0.75},"scanner_precision_by_slug":{"command-injection":1,"flask-route":0,"go-command-injection":1,"go-http-handler":0,"go-ssrf":1,"insecure-crypto":1,"open-redirect":1,"path-traversal":1,"python-eval-exec":1,"sql-injection-string-concat":0.5,"ssrf":1},"false_positive_by_slug":{"flask-route":6,"go-http-handler":4,"sql-injection-string-concat":1},"false_negative_by_slug":{"crypto-random-insecure":1,"sql-injection-string-concat":1},"scanner_uncovered_issues":1,"output_dir":"bench/out/20260512T195728Z","candidate_explosion_threshold":100}
```

## Matcher Lint

Latest run: `go run ./cmd/benchsec lint-matchers --format tsv`

No error-level findings. Warnings found: 17 noisy matchers without a `requires.*` or `require_content` gate, including `ssrf`, `path-traversal`, `open-redirect`, `go-http-handler`, and `flask-route`-style framework surfacing rules.

## Tradeoffs

- Precision is candidate-based, while recall is issue-based. Multiple candidates can still be visible as noise even when only one recall hit is credited.
- The task fixtures intentionally keep route-handler matchers active, so the first baseline exposes noisy framework candidates instead of hiding them with matcher filters.
- `task.toml` supports matcher include/exclude filters, but not tech override plumbing; the starter tasks use normal manifest files to trigger tech detection.

## Surprises

- Existing CLI e2e tests need an executable temp directory in this environment; `/tmp` rejects the built test binary, but `TMPDIR=$PWD/.tmp go test ./...` passes.
- The broad SQLi matcher can fire on unrelated template-string code, which shows up as a per-slug FP in the TypeScript task.
- The Flask and Go route matchers dominate false positives, making the noisy-gate linter warning immediately actionable.
