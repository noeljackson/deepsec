# Rust implementation

See [../MIGRATION.md](../MIGRATION.md) for the full migration guide.

## Build

```
cargo build --release
./target/release/deepsec --help
```

## Test

```
cargo test --workspace
```

## Layout

- `deepsec-core` — types, paths, persistence
- `deepsec-scanner` — file walking + matchers
- `deepsec-processor` — AI backends (Anthropic + OpenAI HTTP)
- `deepsec-cli` — binary

Bundled matchers live under `deepsec-scanner/matchers/*.toml` and are
embedded at compile time via `include_str!`.
