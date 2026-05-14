## External-scanner comparison: Codex Cyber vs deepsec on codewiresh/platform

A 542-finding export of OpenAI's Codex Cyber (Daybreak-family) scan
of `codewiresh/platform` lets us do a real-codebase comparison
against deepsec's regex+AST scan layer. The repo is ~21 GB, mixed
Go + TypeScript + Rust + Python + Swift + Java.

Both scans were taken on 2026-05-14. The deepsec side is regex+AST
only (no AI processing).

### Important caveat: many Codex findings are intentional design

The `codewiresh/platform` repo is a developer-sandboxing platform.
It intentionally:

- mounts the host Docker socket into untrusted workspace containers
  (the sandbox boundary is below this, not above it),
- gives workspace containers broad capabilities,
- vendors credentials into deployment manifests for the platform's
  own service accounts,
- runs CI workflows that operate on attacker-supplied workspace
  contents under explicit sandboxing.

A non-context-aware scanner can't distinguish "exposes Docker socket
to untrusted code (BUG)" from "exposes Docker socket because that's
the platform's purpose (DESIGN)." Codex Cyber flags many of these as
findings; this is real noise, not real signal.

This is in fact the wedge deepsec is built around: the AI
investigation phase, the skeptic second-pass (#62), and the
revalidate stage exist *specifically* to filter design-as-vuln
noise that pure-LLM scanners produce. A raw count comparison is
unfair to both sides.

### Quick numbers

| Scanner       | Findings | Files touched |
|---------------|---------:|--------------:|
| Codex Cyber   |      542 |           358 |
| deepsec       |       87 |            44 |

### File-level coincidence

At HEAD, 191 of the 358 Codex-touched files still exist. Of the 294
Codex findings on those extant files, 82 (27.9%) sit in files
deepsec also flagged at least one candidate in. Of 16 files both
scanners hit, only 4 align on a guessed vuln class — the other 12
are file-coincidences where each scanner caught something different.

**Don't read 27.9% as a recall number.** Without knowing which Codex
findings are real bugs vs intentional design, file overlap is a
coincidence rate, not a recall rate. The denominator is inflated by
design-as-findings.

### Where the comparison is actually informative

**deepsec has genuine signal Codex didn't surface**:

| Vuln class               | Codex (HEAD) | deepsec | Notes |
|--------------------------|-------------:|--------:|-------|
| supply-chain (curl-pipe) |            0 |       6 | Pure deepsec hits — `RUN curl … \| sh` in Dockerfile.{dev,local,workspace} |
| tls-skip-verification    |            3 |      14 | deepsec is more aggressive on `InsecureSkipVerify` — most are tests |
| command-injection        |           40 |      32 | Comparable footprint; sample-checking needed |

The dockerfile-curl-pipe finds in particular are honest scanner
wins: pulling a script over HTTP and piping to shell is a supply
chain footgun even in a "trusted" Docker build context.

**deepsec has plausible coverage gaps regardless of intent**:

| Vuln class               | Codex (HEAD) | deepsec | Reading |
|--------------------------|-------------:|--------:|---------|
| open-redirect            |            1 |       0 | One real instance (dashboard `return_to` param); should have a matcher |
| path-traversal           |            1 |       0 | One instance; matcher exists in jvm.toml but not for general Go/TS path handling |
| sqli                     |            1 |       2 | deepsec actually catches it |

**Categories where Codex flagged a lot, but at least some are
intentional**:

| Vuln class               | Codex (HEAD) | Likely real |
|--------------------------|-------------:|-------------|
| docker-socket            |           12 | Most are intentional (sandbox below the socket) |
| k8s-rbac                 |           17 | Mix: controller perms intentional, dashboard exposure isn't |
| ci-workflow              |           20 | Mix: workspace-runner permissions intentional, manifest-callback unauth is real |
| auth-flow (OAuth/OIDC)   |           30 | Mostly real — the GitHub-OAuth-takeover finding is genuine (the critical #2 in the export) |
| hardcoded-secret         |           27 | Mix: dev fixtures vs real |

The auth-flow gap is the most honest signal: deepsec has zero
matchers for OAuth/OIDC/JWT flow correctness, and at least one of
Codex's findings in this category is a genuine `critical` (the
unauthenticated GitHub OAuth app takeover at
`apps/cli/internal/oauth/manifest.go`). Even in a sandbox-platform
repo, auth-flow bugs aren't intentional.

### What to actually do with this

1. **Pick the categories where we're confident the gap is genuine
   regardless of platform intent**, and file matcher follow-ups for
   those. Strong candidates: OAuth/OIDC manifest-callback unauth,
   open-redirect on user-supplied return URLs, generic path
   traversal on Go/TS file APIs.

2. **Don't chase the docker-socket / k8s-rbac / ci-workflow
   categories on this fixture** — they need a different repo (a
   non-sandbox-platform codebase) to give a clean read.

3. **Confirm the deepsec-only "wins" are real** — run
   `process --skeptic` on the 28 deepsec-only files. The skeptic
   will demote/drop the FPs and leave honest signal.

4. **Use the platform-as-validation pattern more carefully** — for
   the next external comparison, pick a non-sandbox-platform target
   so design-as-finding noise is lower (Juice Shop is intentionally
   vulnerable; Mastodon, Caddy, or any normal server app would give
   a cleaner recall read).

### How to reproduce

```bash
# Codex CSV exported manually from the Codex Cyber UI.
deepsec scan --project-id platform

# Compare deepsec scan candidates against the Codex CSV by file:
python3 scripts/external-comparison.py \
  ~/src/codex-security-findings-*.csv \
  data/platform/files
```

(The `scripts/external-comparison.py` adapter is checked in alongside
this doc. A proper Go-based `bench/cmd/external-compare/` for
repeatable comparisons is a follow-up.)

### Notes on the methodology

- Codex Cyber emits free-text titles + descriptions. The comparison
  adapter buckets each finding into a class via keyword matching;
  this is lossy — 268 of 542 fall into `other`. The visible classes
  are aligned to deepsec's slug taxonomy.
- The `relevant_paths` field lists every file a finding touches, not
  just the sink. We treat any of them as "file flagged."
- Vuln-class alignment isn't reliable across scanners — different
  taxonomies. File-coincidence + visual inspection of the title is
  what we actually use to judge agreement.
