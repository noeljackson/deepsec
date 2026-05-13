# Changelog

## v0.1.0 — 2026-05-13

Initial public release. Notable surface:

### Pipeline

- `deepsec scan` — regex + AST matchers, tech-gated, with a file-hash
  cache that skips matchers on unchanged files (PR #64).
- `deepsec process` — AI investigation. Supports agentic tools
  (`--tools`, PR #58), adversarial second-pass review (`--skeptic`,
  PR #62), multi-model ensemble (`--agents <csv>`, PR #69), and CI
  thresholds (`--fail-on HIGH`, PR #65).
- `deepsec patch` — turns findings into validated source diffs
  (`patch --apply` commits on `deepsec-patch/<finding-id>`, `--push`
  opens a PR via `gh`). PR #59.
- `deepsec report` — markdown / JSON / CSV (default), `--format html`
  (PR #63), `--format soc2|ssdf` for HMAC-signed compliance manifests.

### Self-improvement loop

- `benchsec agent --mode precision` — bounded matcher-patch agent
  (narrow recurring FPs).
- `benchsec agent --mode recall` — bounded new-matcher proposer
  (catch recurring FNs). PR #61.

### Coverage

- AST grammars: Go, TypeScript, TSX, JavaScript, JSX, Python, Rust,
  Java (PRs #51, #56, #60). Kotlin/Swift/C/C++ are matcher-only for
  now; the WASM grammar pipeline is on the roadmap.
- Bundled matcher pack across 12 languages. Sparse tier emptied in
  this release (PRs #66, #67, #70).
- Lightweight per-language taint pre-filter via
  `require_taint_within` (PR #68).

### Operational

- `.pre-commit-hooks.yaml` for local feedback (PR #65).
- `docs/ci-integration.md` end-to-end walkthrough for GitHub Actions.
- Real-world validation against OWASP Juice Shop in
  `docs/juice-shop-validation.md`.

### Origin

deepsec started as a Vercel-internal TypeScript prototype for
AI-assisted security review of large monorepos. Rewritten in Go for
distribution as a single static binary that fits the distroless /
CI-image story.
