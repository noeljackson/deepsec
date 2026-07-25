# External-codebase scans

Each entry here is deepsec run against a real public codebase. The
artefacts: a methodology + findings writeup, the HTML report, and (per
issue #90) any findings worth promoting to bench tasks land in
`bench/tasks/` with `[provenance]` pointing here.

The purpose isn't competitive comparison — it's collecting honest
evidence of what deepsec catches in the wild, what it misses, and
where the matcher pack drifts away from production patterns.

## Batches

- [2026-07-25: AV offline credential-broker assessment](./2026-07-25-av-offline.md) — Rust/Axum, Svelte, Helm, Infisical, and OpenBao boundary review; one confirmed child-environment credential-inheritance finding.
- [2026-05-14: first batch](./2026-05-14-first-batch.md) — Express,
  Flask, Rails, Next.js, jwt-go. Cadence baseline.

## How to add a scan

```bash
git clone --depth 1 https://github.com/<owner>/<repo>.git ~/src/<id>
# Add to deepsec.config.toml [[projects]]
deepsec scan --project-id <id>
deepsec process --project-id <id> --agent zai-coding \
  --only-slugs <high-signal-slugs> --skeptic --max-cost-usd 2
deepsec report --project-id <id> --format html --output docs/scans/<id>-site
```

Write a section in the next batch doc (or a fresh dated doc) with:

1. Repo + commit + scan date
2. Tech tags + matcher count + candidate density
3. Top slugs by candidate count, with one-line judgement
4. Notable findings — full title, file, line, severity, AI rationale
5. **Recall gaps**: things you read in the source that deepsec missed
6. **Precision gaps**: candidates the AI / skeptic dropped (and why)
7. Corpus candidates: per #90's discipline, any finding promotable to a `bench/tasks/<id>/` fixture, with the link to file the metadata

Cadence: monthly batch, 3-5 repos. Repeat sources kept fresh (re-pin SHA, re-score, diff against prior).
