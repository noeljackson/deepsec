# Bake-offs: parallel AI implementations as a design tool

For research-heavy or design-sensitive tasks, running three independent
AI sessions on the same brief and comparing the outputs is often more
useful than iterating one session forever. The first independent
implementation we shipped, the scanner-only evaluation harness in
[`bench/`](../bench/README.md), was selected from a three-way bake-off
(see [#4](https://github.com/noeljackson/deepsec/issues/4) and
[#5](https://github.com/noeljackson/deepsec/pull/5)).

This page documents how we run them.

## When to use a bake-off

A bake-off pays off when **all three** of the following hold:

1. The task is well-specified — you can write a brief that's unambiguous
   enough that three implementations can be compared on the same axes.
2. The deliverable is **load-bearing** — its design will be lived with
   for a while, and getting it wrong is expensive (think public API,
   schema, scoring math, prompt structure).
3. Token cost is not a blocker — either the work is small enough to fit
   in one turn per session, or you're on subscription billing.

Skip it for routine code changes, time-sensitive fixes, or anything
where the answer is obvious. The judging step itself is real work.

## What you need

- The `cw` CLI (codewire) with a local target. Memory file
  [`cw-drive-codex.md`](https://github.com/anthropics/claude-code) has
  the JSON-RPC recipe and gotchas.
- `codex` CLI installed and authenticated.
- One git worktree per session (we use three).
- Disk space for N copies of the repo.

## The recipe

### 1. Write the brief once

Compose `/tmp/bake-brief.md` with:

- **Context**: what's already true, links to issues, the design
  constraints that motivate this work
- **What to build**: numbered list of concrete deliverables
- **Out of scope**: anything the sessions might be tempted to expand into
- **Constraints**: language-version requirements, RE2 vs PCRE, any
  patterns to avoid, files they may *not* touch
- **Acceptance criteria**: how you'll judge done (builds, tests,
  artifact present, LOC budget)
- **Deliverable**: commit to branch, write `BENCH-RESULTS.md` at repo
  root with metrics, do NOT push or merge

Keep the brief tight enough that three independent attempts can be
compared on equal footing, but loose enough that schema/structure
choices are theirs to make. Those choices are exactly what you're
shopping for.

If the bake-off follows a prior design critique (e.g. a codex review on
the original plan), reference that critique in the brief. All three
sessions should share the same context, just not know about each other.

### 2. Create worktrees

```bash
cd <repo-root>
for tag in A B C; do
  git worktree add ../<repo>-bake-$tag -b bake/<topic>-$tag
done
cp /tmp/bake-brief.md ../<repo>-bake-A/.bake-brief.md
cp /tmp/bake-brief.md ../<repo>-bake-B/.bake-brief.md
cp /tmp/bake-brief.md ../<repo>-bake-C/.bake-brief.md
```

The brief lives inside each worktree because the codex session's
working directory is set to the worktree, and the transport between
`cw send` and the session caps at 4096 bytes per message — too small
for any meaningful brief. Pointing at a file on disk is the standard
move.

### 3. Launch sessions

```bash
cw use local

for tag in A B C; do
  cw exec local --name codex-bake-$tag \
    --workdir <abs path to>/../<repo>-bake-$tag \
    -- codex app-server -c model=gpt-5.5 &
done

# Capture numeric session IDs — names go stale after kill+relaunch
cw list --local | grep codex-bake
```

Pin the model so all three runs are comparable. `gpt-5.5` with
reasoning effort high is the current default for this kind of design
work.

### 4. Init, start threads, send the prompt

```bash
# For each session id (e.g. 540, 541, 542):
echo '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{"clientInfo":{"name":"dispatcher","version":"0.1"}}}' \
  | cw send <sid> --stdin --no-newline

echo '{"jsonrpc":"2.0","id":2,"method":"thread/start","params":{"cwd":"<absolute worktree path>","approvalPolicy":"never","sandbox":"danger-full-access"}}' \
  | cw send <sid> --stdin --no-newline

# Grab the thread ID from logs
TID=$(cw logs <sid> --tail 50 | grep -oE 'thread/started"[^}]*"id":"[a-f0-9-]+"' | head -1 | sed 's/.*"id":"//' | tr -d '"')

# Send the same short prompt to each thread
PROMPT='Read .bake-brief.md and execute it end-to-end. Commit your work. Write BENCH-RESULTS.md at the repo root with what you built and the metrics. Do not push.'
printf '{"jsonrpc":"2.0","id":3,"method":"turn/start","params":{"threadId":"%s","input":[{"type":"text","text":%s}]}}\n' \
  "$TID" "$(printf '%s' "$PROMPT" | jq -Rs .)" \
  | cw send <sid> --stdin --no-newline
```

Send by **numeric session ID**, not name, especially after any
`cw kill`. The name → id mapping can go stale and silently route to a
dead session.

### 5. Wait

A reasonable wait loop:

```bash
until [ -s ../<repo>-bake-A/BENCH-RESULTS.md ] && \
      [ -s ../<repo>-bake-B/BENCH-RESULTS.md ] && \
      [ -s ../<repo>-bake-C/BENCH-RESULTS.md ]; do
  sleep 30
done
```

Run in the background. With three parallel `gpt-5.5`-reasoning-high
sessions on a mid-sized design task, total wall time is typically
10–25 minutes.

### 6. Judge

For each worktree:

1. **Does it build and test?** Run the same gates the brief required
   (`go build && go test ./... && go vet`) in each worktree.
2. **Did it commit?** `git log --oneline main..HEAD` should show one or
   more commits. Sessions often forget the final `git commit`; if so,
   that costs them.
3. **Did it stay in scope?** `git diff --stat main..HEAD` — anything
   modified outside the brief's edit surface is a yellow flag. Some are
   defensible (an environmental fix), others aren't.
4. **Compare the deliverable artifacts** side by side:
   - The headline metrics from each `BENCH-RESULTS.md`
   - LOC (`find <dir> -name '*.go' | xargs wc -l`)
   - File organization
   - Schema design (if relevant)
   - Test coverage
5. **Pick the winner.** Compliance with the brief comes first, then
   design quality, then metrics. Don't reward a thinner benchmark just
   because its numbers look prettier.
6. **Cherry-pick** — even the runners-up usually contain ideas worth
   keeping. Note them and pull them in as follow-ups.

### 7. Ship and clean up

```bash
# Push the winning branch
git -C ../<repo>-bake-<winner> push -u origin bake/<topic>-<winner>

# Open the PR with a body that links the issue, summarises the bake-off,
# and lists cherry-picks deferred to follow-ups
gh pr create --base main --head bake/<topic>-<winner> ...

# Kill the sessions
for sid in 540 541 542; do cw kill $sid; done

# Worktrees: keep around if you want to mine the runners-up later
git worktree remove ../<repo>-bake-A   # etc.
```

## A few hard-earned lessons

- **Three is the sweet spot.** Two is hard to break ties; four+ doesn't
  add design diversity that justifies the judging cost.
- **Don't tell them they're in a bake-off.** They'll homogenize toward
  what they think is "expected" or try to be cute. Independent samples
  are the whole point.
- **The brief is the artifact.** A well-written brief produces three
  good attempts. A vague brief produces three rambling ones. Spend
  time on the brief; copy-paste it across worktrees verbatim.
- **Decoys are cheap and load-bearing.** When a brief asks for
  "fixtures with planted issues + decoys", sessions often skimp on the
  decoys. Without them, precision metrics are fake. If decoys are
  important, say "non-negotiable" — and still expect to have to police
  it during judging.
- **Compliance with the brief always wins ties.** A clean commit on
  the correct branch beats clever design that forgot to ship.

## The case study (issue #4 / PR #5)

The scanner-only evaluation harness in `bench/` was selected from a
three-way bake-off in May 2026. Same brief, three parallel `gpt-5.5`
sessions on three worktrees, blind to each other. Selection criteria:

- **Compliance**: only two of three committed cleanly; one stopped
  after `git add`.
- **Decoy density**: 9 vs 4 vs 6 across three tasks. The "non-negotiable"
  framing in the brief still wasn't enough on its own.
- **Schema fidelity**: two of three used the nested `location:` block
  from the design critique; one flattened it.
- **Linter judgment**: same checks, different severities. The winner
  treated duplicate slugs as `error`; the others as `warning`.
- **Code organization**: cleanest separation of `answer.go`,
  `lint.go`, `score.go` won the structural call.

Two ideas from the runners-up were noted for cherry-pick:
- A separate `report.go` for the report writer (B)
- `kloc` and `detectable_issues` fields on per-task output (B)
- Per-task per-slug TP/FP/FN breakdown (C)
- An explicit `safe-decoys.*` source file per task (C)
- A `/tmp`-noexec workaround for the CLI e2e tests (B — accidentally
  useful, since we hit that exact problem during the bake-off itself)

The runners-up cost some token spend but produced design feedback that
would have been hard to extract from one session alone.
