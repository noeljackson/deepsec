# Getting started

## Install

Requires **Rust 1.75+**. Either build from source:

```bash
git clone https://github.com/noeljackson/deepsec
cd deepsec
cargo install --path crates/deepsec-cli
```

…or build a binary locally and copy it where you want:

```bash
cargo build --release
cp target/release/deepsec ~/.local/bin/
```

## Initialize a project

From inside the repo you want to scan:

```bash
deepsec init --project-id myproj --root .
```

That writes `deepsec.config.toml` in the current directory. Edit it to
set a `github_url`, project context (`info_markdown`), and any
`priority_paths`.

## Scan

```bash
deepsec scan --project-id myproj
```

The scanner walks the project root, runs the bundled regex matchers
gated on detected tech, and writes a `FileRecord` JSON per file under
`data/myproj/files/...`.

## Investigate

Set the appropriate API key and run `process`:

```bash
export ANTHROPIC_API_KEY=sk-ant-...
deepsec process --project-id myproj --agent anthropic --concurrency 4
```

Or use OpenAI:

```bash
export OPENAI_API_KEY=sk-...
deepsec process --project-id myproj --agent openai
```

Set `OPENAI_BASE_URL` to point at Azure OpenAI / OpenRouter / vLLM / a
local llama.cpp server.

## Report

```bash
deepsec report --project-id myproj
deepsec metrics --project-id myproj
```

Reports are written under `data/myproj/reports/`. `export` gives you a
filtered JSON dump for downstream pipelines.

## PR workflow

```bash
deepsec scan --project-id myproj --diff origin/main
deepsec process --project-id myproj --diff origin/main
deepsec pr-comment --project-id myproj --output pr-comment.md --skip-empty
```

The `--diff` flag bounds work to files changed against the given git ref.
`pr-comment` renders markdown filtered to net-new findings from the
most recent process run.
