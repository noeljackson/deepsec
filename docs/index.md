# Docs map

Start here. Everything is one click away.

## Start here

- [`getting-started.md`](getting-started.md) — install + first scan
- [`configuration.md`](configuration.md) — `deepsec.config.toml` reference
- [`troubleshooting.md`](troubleshooting.md) — "doctor reports X, what does it mean?"
- [`operational.md`](operational.md) — `deepsec doctor` + `deepsec spend` reference
- [`faq.md`](faq.md) — quick answers

Run `deepsec doctor` first if anything looks wrong. Its output maps
directly to entries in troubleshooting.md.

## Day-to-day

- [`writing-matchers.md`](writing-matchers.md) — regex matcher TOML
- [`writing-ast-matchers.md`](writing-ast-matchers.md) — tree-sitter S-expression queries
- [`patch-generation.md`](patch-generation.md) — `deepsec patch` flow
- [`agentic-tools.md`](agentic-tools.md) — `--tools` investigation mode

## CI integration

- [`ci-integration.md`](ci-integration.md) — pre-commit hook, GitHub Actions, `--fail-on`
- [`compliance-reporting.md`](compliance-reporting.md) — SOC2 / SSDF signed manifests

## Bench & corpus

- [`bench-task-format.md`](bench-task-format.md) — task.toml schema, provenance + label review
- [`bench-corpus-brief.md`](bench-corpus-brief.md) — original plan brief (history)
- [`bench-corpus-critique.md`](bench-corpus-critique.md) — codex GPT-5.5 critique that reshaped the plan
- [`matcher-review.md`](matcher-review.md) — `benchsec review` human-loop CLI
- [`bounded-patch-agent.md`](bounded-patch-agent.md) — `benchsec agent --mode precision`
- [`auto-learn-loop.md`](auto-learn-loop.md) — one-screen tour of the full loop

## Internals & architecture

- [`architecture.md`](architecture.md) — package layout, data flow
- [`data-layout.md`](data-layout.md) — on-disk JSON schema under `data/`
- [`refreshing-grammars.md`](refreshing-grammars.md) — rebuilding tree-sitter WASMs
- [`rfcs/`](rfcs/) — RFC 001 (AST matching) and successors

## Evidence

These docs record what deepsec found on real codebases. Useful both as
validation and as input to corpus growth:

- [`juice-shop-validation.md`](juice-shop-validation.md) — OWASP Juice Shop scan + skeptic + ensemble run
- [`external-comparison.md`](external-comparison.md) — Codex Cyber vs deepsec on codewire/platform
- [`scans/`](scans/) — public-OSS scan writeups, by date

## Process

- [`bake-off.md`](bake-off.md) — three-codex bake-off pattern used for substantial PRs
- [Contributing](../CONTRIBUTING.md) and [Security](../SECURITY.md) at the repo root

---

If a doc you want isn't here, file an issue with the
[`docs`](https://github.com/noeljackson/deepsec/labels/docs) label.
