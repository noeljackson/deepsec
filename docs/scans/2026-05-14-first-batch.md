# First-batch scans — 2026-05-14

deepsec v0.1.0 run against five popular OSS repos to surface real-world
recall + precision signal. Per issue #98. All scans use the same
flow: `scan` → `process --skeptic --max-cost-usd 2` over a focused
slug set, `report --format html`.

Backend: `zai-coding` (Z.ai Coding-Plan flat-rate Anthropic-compatible
endpoint). Cost: ~$0 on the subscription.

## Summary

| Repo | SHA | Files | Cands | Cands→Findings | Notable |
|------|-----|------:|------:|---------------:|---------|
| [expressjs/express](#express) | `f873ac23` | 209 | 333 | 4 → 6 | open-redirect via Referrer in 2 examples; credential leak in error message |
| [pallets/flask](#flask) | `9fcd34c9` | 221 | 19 | 2 → 0 | skeptic dropped all 5 first-pass findings as test/fixture noise |
| [rails/rails](#rails) | `985e510d` | 4695 | 200 | 78 → 7 | 6 HIGH/MEDIUM YAML/Marshal deserialization paths in activesupport + activerecord |
| [vercel/next.js](#nextjs) | `2e90936d` | 26278 | 1300 | 23 → 7 | 1 HIGH command-injection, 5 dangerous-html, 2 open-redirect-draft-mode |
| [golang-jwt/jwt](#jwt-go) | `1d7bc3f7` | 72 | 18 | 5 → 0 | skeptic correctly identified all 17 `secret-plaintext` hits as test-only |

Aggregate: 27,475 files scanned, 1,870 candidates, **20 surviving
findings** post-skeptic, ~3 minutes of wallclock scan + ~12 minutes of
process. Zero dollar cost on the Coding-Plan subscription.

## express

- Repo: `expressjs/express`
- SHA: `f873ac23124ffcff8c040b4bd257b32c29828d53`
- Tech tags: express, github-actions, node
- Matchers active: 106 (21 skipped)

```
scan files=209 candidates=333
process batches=2 files_analyzed=4 findings=6
```

Most candidates (248) came from `express-route` which is the noisy-tier
"there is a route here" matcher — useful for *gating* but not a
finding. The substantive surface narrows to ~85 across `open-redirect`,
`missing-rate-limit`, `missing-csrf-protection`,
`http-only-cookie-missing`, `error-message-leak`.

After AI investigation + skeptic, **6 findings, all in
`examples/`**:

| Severity | Slug | File | Line | What |
|----------|------|------|------|------|
| MEDIUM | `open-redirect` | `examples/auth/index.js` | 119 | `res.redirect(req.get('Referrer') || '/')` after login |
| MEDIUM | `open-redirect` | `examples/route-separation/user.js` | 46 | `res.redirect(req.get('Referrer'))` on update |
| MEDIUM | `information-disclosure` | `examples/auth/index.js` | 122 | login error reveals whether username exists |
| MEDIUM | `missing-rate-limit` | `examples/auth/index.js` | 104 | login endpoint no throttling + credential hint in error |
| MEDIUM | `sensitive-data-in-url` | `examples/web-service/index.js` | 31 | API key as query param |
| LOW | `http-only-cookie-missing` | `examples/cookies/index.js` | 43 | `remember` cookie missing HttpOnly/Secure |

### Judgement

These are **all real anti-patterns** even though they're in
`examples/`. Anyone copy-pasting the Express auth example into a
production app would ship the open-redirect and the credential-hint
leak.

### Recall gap surfaced

The two `open-redirect` hits are caught by the *older* `open-redirect`
matcher (regex). The new
`open-redirect-assign-from-query` matcher I shipped in PR #83 covers
`res.redirect(req.query.…)` but **does not** match
`res.redirect(req.get('Referrer'))` — different request-shape, same
vuln family. Filed as a follow-up.

### Promotable to corpus

The Referrer-redirect pattern is an excellent candidate for a new
bench task: it's a real Express idiom, the safe variant is just an
allowlist check, and the minimal repro is two lines. Will file under
#84 with `[provenance].source = "external-scan"`.

## flask

- Repo: `pallets/flask`
- SHA: `9fcd34c9f3065640bd1cd86234216ca068633fb9`
- Tech tags: flask, github-actions, python
- Matchers active: 106 (21 skipped)

```
scan files=221 candidates=19
process batches=3 files_analyzed=2 findings=0
```

Flask is a small framework. Candidate breakdown: 11 `debug-endpoint`
(by design — Flask's debug config is a feature, not a bug), 3
`missing-csrf-protection` (Flask doesn't bundle CSRF; users add
flask-wtf), 2 `python-eval-exec`, 2 cookies, 1 `insecure-crypto`.

After process + skeptic: **0 findings**. The skeptic correctly
dropped every first-pass hit — `python-eval-exec` was on Flask's own
test fixtures evaluating Jinja2 templates, `insecure-crypto` was on
`werkzeug`'s legacy session signing, etc.

### Judgement

Honest read: Flask is small and clean. The skeptic doing its job.
This is the test case for "don't produce false confidence on a small
codebase."

### Promotable to corpus

Nothing actionable from this scan. Useful as a **negative
fixture**: 0 findings means deepsec doesn't fire on Flask's clean
core, which is a precision signal we should preserve.

## rails

- Repo: `rails/rails`
- SHA: `985e510db4331798e5bf43b892cef9ede7dca43f`
- Tech tags: github-actions, node, ruby
- Matchers active: 105 (22 skipped)

```
scan files=4695 candidates=200
process batches=38 files_analyzed=78 findings=7
```

The headline result: **6 of 7 findings are deserialization paths
(YAML.unsafe_load, Marshal.load) in activesupport + activerecord**.
This family was the source of CVE-2013-0156 — Rails' most famous RCE.
Today's code paths still exist in cache/serializer fallback code,
schema cache loading, and XML mini parser.

| Severity | Slug | File | Line | What |
|----------|------|------|------|------|
| HIGH | `rce-deserialization` | `activesupport/lib/active_support/xml_mini.rb` | 84 | `YAML.unsafe_load` in XMLMini |
| HIGH | `rce-deserialization` | `activerecord/lib/active_record/connection_adapters/schema_cache.rb` | 228 | `Marshal.load` / `YAML.unsafe_load` from file |
| HIGH | `rce-deserialization` | `activesupport/lib/active_support/cache/coder.rb` | 123 | cache deserialize |
| HIGH | `rce-deserialization` | `activesupport/lib/active_support/messages/serializer_with_fallback.rb` | 48 | messages serializer fallback |
| MEDIUM | `rce-deserialization` | `activesupport/lib/active_support/cache/entry.rb` | 155 | entry deserialize |
| MEDIUM | `rce-deserialization` | `activesupport/lib/active_support/cache/serializer_with_fallback.rb` | 39 | serializer fallback |
| LOW | `insecure-crypto` | `activestorage/lib/active_storage/service.rb` | 172 | MD5 used (cache-key context) |

### Judgement

These are **honest signals on known-vulnerable patterns**, but Rails
ships them deliberately — each one has a callsite gate (e.g.
`Marshal.load` only on data the framework wrote itself) that the
AI didn't have context to verify. A second-pass with multi-file
context (the #87 dataflow ceiling) is what's needed to mark these
true-positives vs intentional-trust-boundary.

The LOW `insecure-crypto` (MD5 in ActiveStorage) is a legitimate
flag in the sense that MD5 isn't great as a cache key in
adversarial contexts.

### Promotable to corpus

The XML Mini `YAML.unsafe_load` is the closest to a textbook
finding. Worth a `ruby-yaml-unsafe-load` matcher in the bundled
pack and a bench task derived from CVE-2013-0156 history.

## nextjs

- Repo: `vercel/next.js`
- SHA: `2e90936dc6e3df14c3ff21af895ddf4fabadeae3`
- Tech tags: express, github-actions, nextjs, node, react, rust, typescript
- Matchers active: 111 (16 skipped)

```
scan files=26278 candidates=1300
process batches=25 files_analyzed=23 findings=17
```

This is the biggest surface. Top candidate slugs are framework-
intentional (`nextjs-server-action` 447, `nextjs-route-no-auth` 310,
`dev-auth-bypass` 194, `next-bypass-middleware` 56). I narrowed
processing to the four substantive families:
`dangerous-html`, `command-injection`, `ssrf`, `secret-in-log`,
`env-exposure`.

Surviving findings:

- **1 HIGH `command-injection`** — shell-command interpolation in a
  build/release script
- **2 LOW `command-injection`** — CLI args in pr-status.js and a git
  diffRevision pass-through
- **6 `dangerous-html`** — `dangerouslySetInnerHTML` in
  examples/templates rendering remote content (hero-post, post-body,
  post-preview). Half are example apps, half are docs site code.
- **2 LOW `open-redirect-draft-mode`** — draft-mode redirects (likely
  intentional, but worth a confirmation)
- **2 LOW `secret-in-log`** — partial secret exposure in a health-check
  log
- **1 MEDIUM `insecure-cookie-flags`** — auth token cookie missing
  security flags

### Judgement

Next.js's surface is enormous and the AI investigation phase did the
heavy lift. The `command-injection` HIGH is worth a manual look at
the actual repo. The `dangerouslySetInnerHTML` finds in
example/blog templates are real-but-low-blast-radius — example code
deepsec is correct to flag, the example author has correct context.

### Recall gap surfaced

The `open-redirect-draft-mode` slug was AI-coined — the matcher
pack doesn't have an explicit "draft mode redirect" slug, and the AI
correctly identified the pattern. Worth a curated matcher for the
Next.js-specific shape.

### Promotable to corpus

The command-injection HIGH (need to inspect the file) is the strongest
candidate. The dangerouslySetInnerHTML examples are borderline.

## jwt-go

- Repo: `golang-jwt/jwt`
- SHA: `1d7bc3f78241edd5844e034eea0a25e4b42b5f95`
- Tech tags: github-actions, go
- Matchers active: 105 (22 skipped)

```
scan files=72 candidates=18
process batches=1 files_analyzed=5 findings=0
```

17 `secret-plaintext` hits + 1 `go-time-comparison`. The skeptic
dropped everything — the 17 secrets are all canonical JWT test
fixtures (`my-secret-key`, etc.) used as test inputs to the signing
verifier, not real secrets.

### Judgement

Correct precision. jwt-go ships test-vector strings that look like
secrets to a regex but are exactly what JWT tests need. The skeptic's
"survived a try-to-disprove-this pass" correctly dropped them.

### Promotable to corpus

Like Flask: nothing actionable, but a useful **negative
fixture** — 0 findings on a small clean library. Pairs with the
precision-pressure point from the codex critique (#89).

## Net new follow-ups from this batch

1. **Filing**: `open-redirect-from-referrer` matcher gap (express
   findings on lines 119/46) — extension of #80's recall set.
2. **Filing**: `nextjs-draft-mode-redirect` Next.js-specific slug.
3. **Filing**: `ruby-yaml-unsafe-load` matcher for activesupport-shape
   deserialization.
4. **Filing**: Corpus task derived from the express examples (Referrer
   open redirect, paired safe variant with allowlist).
5. **Filing**: Negative fixture corpus tasks from flask + jwt-go.
6. **Sequencing note**: #87 (multi-file taint) would unlock judging
   the Rails deserialization findings as true vs intentional-trust.

Each gets a separate issue filed against the v0.2 milestone.

## HTML reports

Locally generated at:

- `docs/scans/express-site/index.html`
- `docs/scans/flask-site/index.html`
- `docs/scans/rails-site/index.html`
- `docs/scans/nextjs-site/index.html`
- `docs/scans/jwt-go-site/index.html`

These are gitignored — local-only artefacts. The per-finding
summaries above are the durable record.
