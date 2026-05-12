# Samples

Copy-paste starting points showing how deepsec looks in practice.

## What's here

- [`webapp/`](webapp/) — a fictional Acme inventory webapp. Shows a
  `deepsec.config.ts` that registers two custom matchers via an in-tree
  plugin, an `INFO.md` for the AI's project context, and a per-project
  `config.json`.

Each sample is self-contained: copy the directory next to your real
project, point `root` at your codebase, and run `pnpm deepsec scan` from
inside.
