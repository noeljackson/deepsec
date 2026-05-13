# Juice Shop validation

[OWASP Juice Shop](https://owasp.org/www-project-juice-shop/) is an
intentionally vulnerable Node.js/TypeScript app with a published
answer key. Running deepsec end-to-end against a fresh clone gives a
real, evidence-rich validation of the scanner.

This document captures the validation run from the v0.1 release prep
(2026-05-13). To reproduce, clone Juice Shop, add it as a project in
`deepsec.config.toml`, and run the pipeline below.

## Reproduce

```bash
git clone --depth 1 https://github.com/juice-shop/juice-shop.git ~/src/juice-shop

cat >> deepsec.config.toml <<'EOF'

[[projects]]
id = "juice"
root = "/home/you/src/juice-shop"
github_url = "https://github.com/juice-shop/juice-shop/blob/master"
EOF

deepsec scan --project-id juice
deepsec process --project-id juice --agent zai-coding \
  --only-slugs sql-injection-string-concat,weak-default-secret,insecure-crypto,http-only-cookie-missing,secret-in-log \
  --max-cost-usd 2.0
deepsec report --project-id juice --format html --output ./juice-report
```

## Scan baseline

```
scan files=1084 candidates=579 cache_hits=0
  tech tags: docker, express, github-actions, node, typescript
  matchers active=104 skipped=21
  by language:
      javascript:   13 files  hits in   1
      typescript:  616 files  hits in  51
          python:    3 files  hits in   0
           other:  452 files  hits in   2
```

Top candidate slugs (regex/AST tier, pre-AI):

| count | slug |
|------:|------|
| 245 | `express-route` |
| 144 | `missing-csrf-protection` |
| 133 | `missing-rate-limit` |
|  27 | `iframe-no-sandbox` |
|  20 | `sql-injection-string-concat` |
|   3 | `weak-default-secret` |
|   2 | `insecure-crypto` |
|   2 | `http-only-cookie-missing` |
|   2 | `dockerfile-mutable-tag` |
|   1 | `secret-in-log` |

Of the 20 SQLi candidates: 15 in deliberately-vulnerable
`data/static/codefixes/*Challenge_*.ts`, 3 in `_correct` variants
(scanner FP — same regex pattern), and 2 in real app routes
(`routes/login.ts`, `routes/search.ts`) — both flagship Juice Shop
SQLi challenges.

## Process findings

After AI investigation on the high-signal slugs (25 files analyzed,
~$0 cost on the `zai-coding` flat-rate plan, ~10s wallclock):

```
process run=... batches=7 files_analyzed=25 findings=19 errors=0
```

### Recall against the known answer key

| Juice Shop challenge | Caught? | Finding |
|----------------------|---------|---------|
| Login Admin (SQLi)   | ✓ CRITICAL | "SQL Injection in login query with broken blocklist (missing return)" |
| Login Jim / Bender   | ✓ HIGH  | "SQL Injection in Login Endpoint via String Interpolation of User Input" |
| Search SQL Injection | ✓ HIGH  | "SQL Injection in Search Endpoint via String Interpolation of Query Parameter" |
| Christmas Special    | ✓ HIGH  | "SQL Injection via string interpolation with broken input validation" |
| XSS Tier 1           | ✓ HIGH  | "Flawed HTML sanitization allows XSS bypass" |
| Forge JWT            | ✓ MEDIUM | "Hardcoded RSA private key in source code" |
| Weak Crypto          | ✓ MEDIUM | "Use of MD5 for password/data hashing" |

### Notable AI reasoning (beyond pattern match)

- **Broken blocklist (missing return)**: AI noticed a control-flow flaw
  where a validation check didn't actually short-circuit. Pure regex
  can't see this — it requires reading the function body.
- **Bypassable filter**: AI flagged inputs sanitised by an
  insufficient denylist. Same: needs the body, not the call site.
- **Open redirect via substring matching on allowlist**: AI
  identified the wrong-string-comparison anti-pattern in the
  allowlist logic.

### Severity distribution

| severity   | count |
|------------|------:|
| CRITICAL   | 1 |
| HIGH       | 8 |
| MEDIUM     | 4 |
| LOW        | 3 |

### Slug distribution

The AI emitted finer-grained slugs than the matcher pack defined.
This is expected — `vulnSlug` on a `Finding` is the AI's
classification of what it actually found, not the matcher slug that
triggered the candidate. Examples:

- `sql-injection-string-concat` (8) — the bundled matcher slug
- `sql-injection-login-bypass` (1) — AI specialised to the login flow
- `sql-injection-bypassable-blocklist` (1) — AI named the filter-bypass class
- `sql-injection-bypassable-filter` (1) — same family, different shape
- `weak-sanitization-xss` (1) — XSS via flawed sanitiser
- `trust-header-email` (1) — header-trust vuln

The recall-improvement loop (`benchsec agent --mode recall`) can
turn these AI-emitted slugs into new bundled matchers for the next
project's scan.

## What's not yet validated

- `--skeptic` — adversarial second pass wasn't run on this fixture.
  The 19 findings are first-pass output. A future run with `--skeptic`
  would tell us how many survive the disprove-it stance.
- `--agents anthropic,zai-coding` — ensemble run wasn't made.
  Consensus-vs-solo split would be useful to see on this corpus.
- The taint pre-filter is opt-in per matcher and isn't applied to
  `sql-injection-string-concat`. Worth measuring the FP delta when
  it is.

These are follow-up evidence-collection runs, not blockers on v0.1.
