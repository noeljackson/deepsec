# Getting started

## Install

Requires **Go 1.25+** to build from source:

```bash
go install github.com/noeljackson/deepsec/cmd/deepsec@latest
```

Or build locally:

```bash
git clone https://github.com/noeljackson/deepsec
cd deepsec
go build -o bin/deepsec ./cmd/deepsec
```

Pre-built binaries for linux/darwin/windows × amd64/arm64 ship per
release. There's also a `Dockerfile` (distroless, ~20 MB).

## Initialize a project

From inside the repo you want to scan:

```bash
deepsec init --project-id myproj --root .
```

That writes `deepsec.config.toml` in the current directory.

## Scan

```bash
deepsec scan --project-id myproj
```

The scanner walks the project root, runs the bundled regex matchers
gated on detected tech, and writes a `FileRecord` JSON per file under
`data/myproj/files/...`.

## Investigate

Set the appropriate env var and run `process`:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
deepsec process --project-id myproj --agent anthropic --concurrency 4
```

Or use any of the other built-in providers:

```bash
export OPENAI_API_KEY=sk-... && deepsec process --project-id myproj --agent openai
export ZAI_API_KEY=... && deepsec process --project-id myproj --agent glm
export MOONSHOT_API_KEY=... && deepsec process --project-id myproj --agent kimi
export DEEPSEEK_API_KEY=... && deepsec process --project-id myproj --agent deepseek
```

Run `deepsec list-providers` to see what's wired up.

## Budget control

Pass `--max-cost-usd 5.00` to abort the run mid-flight when cumulative
spend exceeds the cap. Real cost is computed from a per-model pricing
table built into the provider profile, so the number is accurate (not a
token estimate).

## Report

```bash
deepsec report --project-id myproj      # markdown + JSON + CSV
deepsec metrics --project-id myproj     # cost / TP-FP rates
deepsec export --project-id myproj --format sarif --output deepsec.sarif
```

## PR workflow

```bash
deepsec scan --project-id myproj --diff origin/main
deepsec process --project-id myproj --diff origin/main
deepsec pr-comment --project-id myproj --output pr-comment.md --skip-empty
```
