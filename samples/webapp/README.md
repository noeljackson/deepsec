# webapp sample

A fictional inventory webapp ("Acme") with deepsec wired up. This is
the **rich reference** — a worked plugin + custom matchers + filled-in
INFO.md showing what a scanning workspace looks like once it's been
loved on for a while.

Files (read in this order):

1. [`package.json`](package.json) — declares `deepsec` as a dependency.
2. [`deepsec.config.ts`](deepsec.config.ts) — loads `INFO.md` inline,
   registers two custom matchers via an in-line plugin.
3. [`matchers/webapp-debug-flag.ts`](matchers/webapp-debug-flag.ts) and
   [`matchers/webapp-route-no-rate-limit.ts`](matchers/webapp-route-no-rate-limit.ts)
   — example custom matchers tuned for this codebase's helpers.
4. [`INFO.md`](INFO.md) — the AI prompt context: auth shape, threat
   model, false-positive sources.
5. [`config.json`](config.json) — optional per-project config
   (`priorityPaths`, `promptAppend`, `ignorePaths`).

## How this relates to `deepsec init`

`deepsec init` produces a **minimal** scaffold inside `.deepsec/` —
config + INFO.md + SETUP.md + env/gitignore. No custom matchers,
no plugin.

This sample is what `.deepsec/` can grow into over time. Read it for
shape; don't copy it as your starting point. The intended flow:

```bash
# Start minimal: from your repo root.
npx deepsec init
cd .deepsec && pnpm install
# Let your agent fill INFO.md, then scan.

# Later, when a true-positive finding suggests a matcher worth keeping,
# look at this sample's matchers/*.ts for the shape, and read
# docs/writing-matchers.md for the workflow that grows it.
```

## Run the sample as-is

From this directory (works because the monorepo symlinks `deepsec` in
for tests):

```bash
pnpm deepsec scan     --project-id webapp --root ./your-app
pnpm deepsec process  --project-id webapp
```

`deepsec` walks up from cwd to find `deepsec.config.ts`, so any
subdirectory works too.
