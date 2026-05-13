# RFC 001: AST-aware matching
Status: Proposed
Owner: scanner
Issue: https://github.com/noeljackson/deepsec/issues/23
Last updated: 2026-05-13

## 1. Motivation
deepsec currently has a deliberately simple scanner.
The scanner walks project files, loads declarative TOML matchers, runs
regular expressions over normalized source text, and writes
`core.CandidateMatch` records for the processor.
That design is visible in the code.
`README.md:6` describes the scanner as producing high-recall candidate
matches.
`README.md:115` says the `scan` stage walks files and runs regex
matchers.
`internal/scanner/matcher.go:41` defines `MatcherDef` as the TOML
record.
`internal/scanner/matcher.go:47` stores only `file_patterns`.
`internal/scanner/matcher.go:48` stores only regex `patterns`.
`internal/scanner/matcher.go:75` documents `Matcher.Match` as a text
matcher.
`internal/scanner/matcher.go:78` takes only `content` and `filePath`.
`internal/scanner/scan.go:94` calls `runMatchers` with text content.
`internal/scanner/scan.go:244` loops active matchers.
`internal/scanner/scan.go:257` appends `m.Match(content, rel)` results.
That simplicity has paid off.
The bundled matcher pack is embedded at compile time.
`internal/scanner/registry.go:14` embeds `matchers/*.toml`.
`internal/scanner/registry.go:36` loads the built-in pack.
`internal/scanner/registry.go:57` decodes user and built-in TOML through
the same path.
`internal/scanner/registry.go:95` lets user matchers override a slug
without changing the pipeline.
The current pack has 82 matchers.
Existing matcher tests compile the bundled pack and assert at least 70
matchers in `internal/scanner/matcher_precision_test.go:34`.
The current count on this branch is 82 `[[matcher]]` tables.
The scanner also preserves a stable on-disk contract.
`internal/core/types.go:108` defines `CandidateMatch`.
`internal/core/types.go:110` stores `vulnSlug`.
`internal/core/types.go:111` stores `lineNumbers`.
`internal/core/types.go:112` stores the source snippet.
`internal/core/types.go:113` stores `matchedPattern`.
`internal/core/types.go:252` defines `FileRecord`.
`internal/core/types.go:258` stores the candidate list.
`internal/core/types.go:261` already stores `fileHash`.
`docs/data-layout.md:28` documents candidates as scanner-emitted regex
hits.
The problem is not that regex is broken.
The problem is that regex is now the wrong abstraction for a growing
part of the matcher pack.
Regex cannot reliably distinguish a function call from a comment.
Regex cannot reliably distinguish an object property named
`dangerouslySetInnerHTML` from a variable or helper string with the same
text.
Regex cannot reliably distinguish a Go handler that merely exists from
a Go handler that contains a request-controlled sink.
Regex cannot reliably distinguish `exec` called with a shell and dynamic
argument from `execFile` or `exec.Command` called with constant argv.
Regex cannot express "the first argument is a selector expression rooted
at `req.query`" without either false positives or false negatives.
Regex cannot express "this query string is concatenated inside the first
argument to a SQL execution call" across nested expression shapes.
The benchmark currently shows this ceiling.
I ran `go run ./cmd/benchsec score` on this branch.
The current scanner scored 0.857 recall and 0.522 precision.
It emitted 23 candidates.
It emitted 16 noisy candidates.
It had 11 false positives.
The false positives were:
- 4 `go-http-handler` candidates.
- 6 `flask-route` candidates.
- 1 `sql-injection-string-concat` candidate.
Those three slugs have a common theme.
The regex can identify a structural site.
It cannot describe the security-relevant relationship inside that site.


### Worked example: Go handlers and command execution
The current Go route matcher is intentionally broad.
`internal/scanner/matchers/go.toml:2` defines `go-http-handler`.
`internal/scanner/matchers/go.toml:4` marks it `noise_tier = "noisy"`.
`internal/scanner/matchers/go.toml:7` matches a `func` that takes
`http.ResponseWriter` and `*http.Request`.
`internal/scanner/matchers/go.toml:8` matches `http.HandleFunc`.
The benchmark answer key marks several Go issues.
`bench/tasks/go-vulnerable-cli/answer.yaml:2` marks command injection
in `handlers.go`.
`bench/tasks/go-vulnerable-cli/answer.yaml:7` marks a hardcoded command
line as a decoy.
The source has both shapes.
The vulnerable shape is a handler that reads `r.URL.Query().Get("term")`
and builds an `exec.Command("sh", "-c", "grep "+term+...)` command.
The safe decoy is `exec.Command("/usr/bin/uptime")`.
The regex route matcher sees both functions as handlers.
It cannot say "only emit a candidate when the handler body contains a
sink call whose argument expression is derived from the request."
The Go-specific command matcher is more precise, but still limited.
`internal/scanner/matchers/go.toml:51` defines `go-command-injection`.
`internal/scanner/matchers/go.toml:56` matches `exec.Command` with a `+`
before the next `)`.
`internal/scanner/matchers/go.toml:57` does the same for
`exec.CommandContext`.
That misses shapes like:

```go
cmd := "grep " + term + " /var/log/app.log"
exec.Command("sh", "-c", cmd)

```

It can also be fooled by formatting or nested expressions.
An AST matcher can match the call node, argument positions, and argument
expression kind directly.
The initial AST version should not try to solve whole-program taint.
It should solve the direct local shapes the benchmark already contains:
- `exec.Command("sh", "-c", <binary expression>)`.
- `exec.Command("sh", "-c", <identifier>)` when the same function assigns
  that identifier from `r.URL.Query().Get(...)`.
- `exec.Command(<dynamic expression>, ...)`.
- Exclude `exec.Command(<string literal>, <string literal>...)`.
This is enough to keep the hardcoded `uptime` decoy quiet.
It is also enough to stop treating every Go HTTP handler as a candidate.


### Worked example: dangerous HTML in React
The current core matcher has the right intent but the wrong abstraction.
`internal/scanner/matchers/core.toml:88` defines `dangerous-html`.
`internal/scanner/matchers/core.toml:91` targets TS, TSX, JS, JSX, Vue,
and Svelte.
`internal/scanner/matchers/core.toml:94` looks for the text
`dangerouslySetInnerHTML = {{ __html`.
`internal/scanner/matchers/core.toml:95` looks for `.innerHTML =` with
request-like identifiers.
`internal/scanner/matchers/core.toml:96` looks for Vue `v-html`.
`internal/scanner/matcher_precision_test.go:94` tests the React
positive case.
`internal/scanner/matcher_precision_test.go:100` tests that normal JSX
text interpolation should not fire.
The regex can catch a simple JSX spelling.
It cannot reason about JSX attribute structure.
It cannot distinguish:

```tsx
return <div dangerouslySetInnerHTML={{ __html: comment.body }} />;

```

from:

```tsx
const propName = "dangerouslySetInnerHTML";
return React.createElement("div", { title: propName }, body);

```

It cannot reliably support:

```tsx
return React.createElement("div", {
  dangerouslySetInnerHTML: { __html: comment.body },
});

```

The matcher needs to match either a JSX attribute named
`dangerouslySetInnerHTML` or an object property with that exact key in
the second argument of `React.createElement`.
It should not fire on arbitrary string mentions.
That is an AST problem, not a better-regex problem.


### Worked example: SQL regex crosses language boundaries
The current SQL matcher is broad.
`internal/scanner/matchers/core.toml:20` defines
`sql-injection-string-concat`.
`internal/scanner/matchers/core.toml:23` targets TS, JS, Python, Ruby,
Go, PHP, Java, and C#.
`internal/scanner/matchers/core.toml:26` looks for query-like calls with
template interpolation containing request-like names.
`internal/scanner/matchers/core.toml:27` looks for query-like calls with
string concatenation.
`internal/scanner/matchers/core.toml:28` looks for Python f-strings.
`internal/scanner/matchers/core.toml:29` looks for Python `%` formatting.
On the current benchmark it has one true positive and one false
positive in the TypeScript task.
The false positive is an `exec(...)` command injection site.
The regex includes `exec` because SQL APIs often use `exec`, but
JavaScript also uses `exec` for command execution and regular
expression APIs.
An AST matcher can separate receiver and callee shapes:
- `db.query(...)`.
- `client.execute(...)`.
- `cursor.execute(...)`.
- `sequelize.query(...)`.
- not bare shell `exec(...)`.
The Python false negative in the benchmark is also structural.
`bench/tasks/py-vulnerable-flask/answer.yaml:4` labels a Python f-string
SQL issue.
The closest current candidate is only `flask-route`.
The regex did not emit the SQL slug.
A Python AST matcher can match a call whose callee attribute is
`execute` and whose first argument is a `f_string` or concatenation node.
It still cannot prove taint in all cases.
It can, however, remove the cross-language `exec` false positive and
cover the direct f-string form.


### Agent evidence
The bounded-patch agent exists to improve matchers without changing the
engine.
`docs/auto-learn-loop.md:104` describes the bounded-patch agent.
`docs/auto-learn-loop.md:110` says one iteration picks a target slug.
`docs/auto-learn-loop.md:112` says the model returns exactly one
structured patch.
`docs/auto-learn-loop.md:113` lists the allowed patch fields.
`docs/auto-learn-loop.md:114` includes `needs-engine-feature`.
`docs/auto-learn-loop.md:125` names the escape valve.
`docs/auto-learn-loop.md:127` explains that no safe TOML edit should be
forced when engine behavior is missing.
`docs/auto-learn-loop.md:133` says the first real live-LLM run returned
`needs-engine-feature` for `flask-route` and `go-http-handler`.
GitHub issue 23 adds `sql-injection-string-concat` as another first-run
structural deferral.
So the live-agent evidence is three slugs:
- `flask-route`.
- `go-http-handler`.
- `sql-injection-string-concat`.
Those are not model failures.
They are useful pressure on the scanner contract.


### Expected impact
AST awareness should immediately move these slugs from engine-limited to
matcher-authorable for direct local cases:
- `go-http-handler`: stop emitting every handler; emit only handlers
  containing configured sink shapes or security-relevant framework
  calls.
- `flask-route`: stop emitting every route; emit route functions with
  direct request-to-sink shapes.
- `sql-injection-string-concat`: distinguish SQL APIs from shell APIs
  and cover language-specific interpolation nodes.
- `go-command-injection`: cover shell argument position and constant
  argv exclusions.
- `command-injection`: split JavaScript command APIs from unrelated
  `exec` callees.
- `dangerous-html`: match JSX attributes and `React.createElement`
  props by syntax, not by text.
- `ssrf`: match direct request-derived argument expressions in `fetch`,
  `http.Get`, `requests.get`, and equivalent APIs.
- `path-traversal`: match file APIs with direct request-derived path
  expressions.
- `python-eval-exec`: exclude `ast.literal_eval` structurally rather
  than by increasingly broad suppressions.
- `tls-skip-verification`: match object and composite literals exactly.
AST awareness should not pretend to solve these cases:
- Cross-function taint from request data into a later sink.
- Aliased imports and wrapper functions unless the alias is local and
  obvious.
- Sanitizer correctness.
- Authorization absence in route handlers.
- Rate-limit absence.
- Environment-dependent routing and middleware ordering.
- SQL query-builder semantics.
- Open redirect allow-list correctness.
- SSRF URL validation correctness.
- Dataflow through collections, closures, goroutines, promises, or
  async callbacks.
The target is not "replace the LLM processor."
The target is "give the processor fewer, better candidates."
On the current benchmark, an AST-aware first pass should remove the 11
structural false positives and recover the Python SQL direct f-string
false negative.
That would take scanner precision from 12/23 to roughly 13/13 on this
small benchmark if no new candidates were added.
That estimate is intentionally bounded to current fixtures.
On real repositories, I expect 5x to 10x false-positive reduction for
the route and direct-sink classes named in issue 23.
I do not expect broad whole-program vulnerability discovery without a
separate dataflow RFC.

## 2. Embedding Strategy Decision
Decision: use tree-sitter grammars compiled to WASM and run them through
wazero.
Use the same WASM path for Go, TypeScript, JavaScript, Python, and Rust.
Do not use `go/parser` for the production Go AST matcher path in this
RFC.
That is the hard call.
The tempting hybrid is rejected.
The reason is product and operational coherence, not raw parser speed.
deepsec's install story is a single Go binary.
`README.md:17` says releases publish binaries for linux, darwin, and
windows across amd64 and arm64.
`README.md:32` says the Dockerfile is distroless and around 20 MB.
`Dockerfile:6` builds with `CGO_ENABLED=0`.
`Dockerfile:8` uses `gcr.io/distroless/static-debian12:nonroot`.
The AST implementation must preserve that invariant.
The query language also must be uniform.
Matcher authors already write one TOML format.
`docs/writing-matchers.md:1` says matchers are declarative TOML records.
`docs/writing-matchers.md:36` documents the schema.
`docs/writing-matchers.md:54` explains RE2 as a known regex flavor.
Adding AST should not create one Go-native query dialect and one
tree-sitter query dialect.
A single tree-sitter query surface across languages is the smallest
authoring model that still has production-grade parsers.


### Current baseline measurements
I built the current binary with:

```bash
go build -trimpath -ldflags='-s -w' -o /tmp/deepsec-rfc-baseline ./cmd/deepsec

```

The stripped baseline binary is 13,574,409 bytes on linux amd64.
That is roughly 13 MiB.
I also benchmarked `go/parser` on a synthetic 500-line Go file because
it is the strongest argument for the hybrid.
The command used `parser.ParseFile` with `parser.SkipObjectResolution`.
Five runs on this machine were:
- 289,092 ns/op.
- 289,845 ns/op.
- 294,280 ns/op.
- 286,095 ns/op.
- 287,558 ns/op.
The allocation profile was about 279 KB/op and 8,641 allocs/op.
So `go/parser` parses a 500 LOC Go file in about 0.29 ms here.
That is excellent.
It is still not worth a second AST abstraction in the first AST
implementation.
I also measured process-spawn overhead using `/bin/true` as the lower
bound.
On this machine:
- 1 spawn took 1.553 ms.
- 10 spawns took 6.334 ms total.
- 100 spawns took 56.640 ms total.
- 1000 spawns took 567.092 ms total.
That is about 0.57 ms per warm spawn before doing any parsing or JSON
marshalling.
A `tree-sitter` sidecar per file would pay more than that.


### Selected option: WASM grammars via wazero
Use wazero as the pure-Go WebAssembly runtime.
Embed one WASM grammar per supported language.
Load and compile grammar modules once per scanner process.
Parse each eligible file once per language.
Run all AST queries for that language against the parsed tree.
Emit the same `core.CandidateMatch` shape that regex emits today.
The initial embedded languages are:
- Go.
- TypeScript.
- TSX.
- JavaScript.
- JSX.
- Python.
Rust follows only after the first two rollout phases are green.
The budget is binary growth of at most 5 MB over the current stripped
binary.
Issue 23 estimates roughly 2.5 MB total for five languages.
The implementation issue must verify that with the exact grammar build
artifacts before merging.
If the first implementation exceeds 5 MB, remove Rust and Python from
the initial embedded set before weakening the binary-size invariant.


### Rejected option: CGo plus native tree-sitter
CGo plus native tree-sitter is the fastest parser path.
It is rejected because it breaks the distribution invariants.
The Dockerfile currently uses `CGO_ENABLED=0` at `Dockerfile:6`.
The final image is distroless static at `Dockerfile:8`.
CGo would add platform-specific native linking and cross-compilation
work for every release target listed in `README.md:17`.
It also makes the scanner harder to run in locked-down environments.
The failure mode is not a small code inconvenience.
The failure mode is that linux/darwin/windows x amd64/arm64 releases no
longer come from the same pure-Go build path.
That is too high a cost for a scanner whose current operational
advantage is easy deployment.


### Rejected option: sidecar process
A `tree-sitter` CLI sidecar preserves the deepsec binary as pure Go.
It is rejected because the scanner walks many files and sidecar startup
cost is paid per file unless a long-running server is introduced.
The current walker includes every source-like file under 1 MiB.
`internal/scanner/walker.go:67` caps individual files at 1 MiB.
`internal/scanner/walker.go:72` walks the full project.
Large repositories can easily produce tens of thousands of eligible
files.
My local lower-bound spawn benchmark is about 0.57 ms per warm
`/bin/true` process.
A real `tree-sitter` CLI invocation would add startup, grammar loading,
parse, and output serialization.
At 100k files, 0.57 ms alone is 57 seconds before useful parsing.
At the issue's 5 ms per-file sidecar estimate, 100k files is 500
seconds.
That is not acceptable for a scan stage that should remain cheap enough
to run before the AI processor.
A long-running sidecar would reduce spawn cost but add lifecycle,
versioning, installation, and sandboxing problems.
That is worse than embedding wazero.


### Rejected option: native parser per language
Native parsers are attractive for Go.
The `go/parser` benchmark above shows about 0.29 ms for a synthetic 500
LOC file.
It is rejected as the general strategy because there is no comparable
stdlib-quality Go-native parser set for TypeScript, Python, Rust, TSX,
and JSX.
Using `go/parser` for Go and tree-sitter for everything else would force
one of two bad outcomes:
- Maintain two query languages.
- Build an adapter that pretends Go ASTs are tree-sitter trees.
The first outcome is bad for matcher authors.
The second outcome is bad for implementation risk.
The first AST release should solve the scanner's structural ceiling, not
invent a portable AST normalization layer.


### Rejected option: hybrid Go-native plus WASM
Hybrid is the option I was most tempted by.
Go is already important in the benchmark.
The Go parser is fast, standard, and dependency-free.
`go-http-handler` and `go-command-injection` are among the clearest
initial wins.
I still reject hybrid for RFC 001.
The reason is that Go would become the special case in every layer:
- Parser interface.
- Query compiler.
- Capture naming.
- Test fixture authoring.
- Documentation.
- Agent patch schema.
- Performance profiling.
- Bug reports.
That is not worth saving roughly 1 ms per parsed Go file in the first
release.
If Go AST matching becomes the dominant production workload and
tree-sitter-go via WASM is proven to be the bottleneck, a future RFC can
introduce a Go-native fast path behind the same TOML query contract.
That future optimization must not change matcher syntax.

## 3. Query Language Decision
Decision: use tree-sitter S-expression queries.
Do not create a custom deepsec AST DSL in RFC 001.
Do not embed Semgrep's pattern language.
Do not expose raw Go code predicates in matcher TOML.
The query engine should support a deliberately small subset of
tree-sitter query features at first:
- Node patterns.
- Named captures.
- Field constraints.
- Alternation.
- `#eq?`.
- `#match?`.
- `#not-eq?`.
- `#not-match?`.
The query engine should reject unsupported predicates at matcher compile
time.
The compile failure should follow the existing matcher behavior:
`internal/scanner/registry.go:50` fails if a bundled matcher cannot load.
`internal/scanner/matcher.go:147` documents that regex compile errors
make `Compile` fail.
AST query compile errors should be equally loud.


### Why tree-sitter queries
Tree-sitter queries are already the native query layer for tree-sitter
trees.
They are language-aware but not deepsec-specific.
They can be validated by external tree-sitter tooling.
They can express real AST shape without a new deepsec language.
They keep implementation scope narrow.
They also make matcher examples portable between docs, tests, and the
tree-sitter ecosystem.


### Query example: Go command injection
The query below is illustrative syntax for tree-sitter-go.
The implementation issue must validate exact node names against the
pinned grammar.
The matcher should match `exec.Command` and `exec.CommandContext` calls
where an argument contains string concatenation or a request-derived
selector call.

```scheme
(
  call_expression
    function: (selector_expression
      operand: (identifier) @pkg
      field: (field_identifier) @method)
    arguments: (argument_list
      [
        (binary_expression) @dynamic_arg
        (call_expression
          function: (selector_expression
            field: (field_identifier) @source_method)) @dynamic_arg
        (identifier) @dynamic_arg
      ])
) @call
(#eq? @pkg "exec")
(#match? @method "^(Command|CommandContext)$")

```

That query alone is not enough to prove taint.
The TOML pattern will therefore label it as direct dynamic command
construction, not proven exploitation.
For the handler benchmark case, a second query can match the local
request source and command sink inside one function body:

```scheme
(
  function_declaration
    parameters: (parameter_list
      (parameter_declaration
        name: (identifier) @request_name
        type: (pointer_type
          (selector_expression
            operand: (identifier) @http_pkg
            field: (field_identifier) @request_type))))
    body: (block
      (short_var_declaration
        left: (expression_list (identifier) @local)
        right: (expression_list
          (call_expression
            function: (selector_expression
              field: (field_identifier) @get_method))))*
      (expression_statement
        (call_expression
          function: (selector_expression
            operand: (identifier) @exec_pkg
            field: (field_identifier) @exec_method)
          arguments: (argument_list (_) (_) (binary_expression) @cmd_arg)))*) 
) @function
(#eq? @http_pkg "http")
(#eq? @request_type "Request")
(#eq? @get_method "Get")
(#eq? @exec_pkg "exec")
(#match? @exec_method "^(Command|CommandContext)$")

```

This is intentionally local.
It does not claim interprocedural dataflow.
It does give the matcher author enough structure to remove the
hardcoded `uptime` decoy.


### Query example: React dangerous HTML
For TSX and JSX, match the JSX attribute form:

```scheme
(
  jsx_attribute
    name: (property_identifier) @attr
    value: (jsx_expression
      (object
        (pair
          key: (property_identifier) @html_key
          value: (_) @html_value)))
) @attribute
(#eq? @attr "dangerouslySetInnerHTML")
(#eq? @html_key "__html")

```

For `React.createElement`, match the props object:

```scheme
(
  call_expression
    function: (member_expression
      object: (identifier) @react
      property: (property_identifier) @create)
    arguments: (arguments
      (_) 
      (object
        (pair
          key: (property_identifier) @prop
          value: (object
            (pair
              key: (property_identifier) @html_key
              value: (_) @html_value)))))
) @call
(#eq? @react "React")
(#eq? @create "createElement")
(#eq? @prop "dangerouslySetInnerHTML")
(#eq? @html_key "__html")

```

This solves a real gap in the current regex.
It also prevents string-only mentions of the prop name from producing a
candidate.


### Query example: Python SQL f-string
The Python grammar should match a call whose callee attribute is
`execute` and whose first argument is an interpolation node:

```scheme
(
  call
    function: (attribute
      attribute: (identifier) @method)
    arguments: (argument_list
      [
        (string
          (interpolation) @interpolation)
        (binary_operator) @concat
      ])
) @call
(#eq? @method "execute")

```

This would cover the Python benchmark false negative described in
`bench/tasks/py-vulnerable-flask/answer.yaml:4`.
It would not decide whether `request.args.get` is sanitized.
That remains processor or future dataflow work.


### Why not a custom DSL
A custom DSL can make simple cases pretty.
For example:

```text
call(exec.Command, arg:any_dynamic)

```

That is easy to read but expensive to own.
deepsec would have to define syntax, semantics, diagnostics,
documentation, editor tooling, and a compiler per language.
The project does not need that burden yet.
The current matcher ecosystem already expects authors to learn RE2.
`docs/writing-matchers.md:54` explicitly documents RE2 limitations.
It is acceptable to document tree-sitter query limitations with the same
level of directness.


### Why not Semgrep patterns
Semgrep-style patterns are attractive because many security engineers
already know them.
They are rejected here because deepsec would either have to embed
Semgrep or reimplement an approximation.
Embedding Semgrep is not compatible with the single static Go binary
goal.
Reimplementing Semgrep patterns would create a second, partial Semgrep.
That is worse than exposing the underlying tree-sitter query model.

## 4. TOML Extension
Decision: extend the existing `[[matcher]]` table with nested
`[[matcher.ast_patterns]]` tables.
Do not introduce a separate top-level `[[ast_matcher]]`.
Do not overload `patterns` as AST queries.
Do not make regex `patterns` act as AST prefilters.
A matcher can contain:
- Text regex candidate patterns.
- AST candidate patterns.
- Both.
- Neither is invalid.
Existing regex-only matcher TOML remains valid.
`patterns` becomes required only when `ast_patterns` is empty.
`ast_patterns` is required only when `patterns` is empty.
If both are present, candidate semantics are OR.
That means regex hits and AST hits both emit candidates for the same
slug.
Deduplication continues to use the existing candidate key:
`internal/scanner/scan.go:310` builds a key from slug, matched pattern,
and line numbers.
If a matcher author wants regex as a cheap AST parse prefilter, they
must use the new `prefilter_patterns` field inside the AST pattern.
They must not use candidate-producing `patterns` for that.
That separation prevents accidental duplicate candidates.


### New fields
`MatcherDef` gains:

```go
ASTPatterns []ASTPatternDef `toml:"ast_patterns,omitempty"`

```

Each `ASTPatternDef` has:

```go
Language          string            `toml:"language"`
Query             string            `toml:"query"`
Label             string            `toml:"label,omitempty"`
PrimaryCapture    string            `toml:"primary_capture,omitempty"`
SnippetCapture    string            `toml:"snippet_capture,omitempty"`
PrefilterPatterns []string          `toml:"prefilter_patterns,omitempty"`
CaptureLabels     map[string]string `toml:"capture_labels,omitempty"`

```

`language` is required.
Accepted initial values are:
- `go`.
- `javascript`.
- `jsx`.
- `typescript`.
- `tsx`.
- `python`.
`query` is required.
`label` defaults to the parent matcher label if present.
If neither AST pattern label nor parent label exists, label defaults to
`ast:<language>:<capture-name>`.
`primary_capture` defaults to `@match`.
`snippet_capture` defaults to `primary_capture`.
`prefilter_patterns` are RE2 patterns run before parsing.
All `prefilter_patterns` in one AST pattern use OR semantics.
If `prefilter_patterns` is empty, the AST pattern is eligible whenever
the file language, matcher gate, and file glob match.
`capture_labels` is future-facing but useful in the first release for
multi-capture query output.
It maps capture names to labels when one query intentionally emits
multiple candidate types.
The first implementation may reject `capture_labels` if it complicates
deduplication.
The TOML shape reserves the field.


### Matcher-level semantics
Existing matcher-level fields apply to both regex and AST paths:
- `slug`.
- `description`.
- `noise_tier`.
- `file_patterns`.
- `exclude_path_patterns`.
- `require_content`.
- `snippet_before`.
- `snippet_after`.
- `label`.
- `requires`.
`file_patterns` remains the first coarse filter.
`exclude_path_patterns` remains a path-only exclusion.
`require_content` remains a file-level text precondition.
`suppress_patterns` applies only to emitted snippet text, regardless of
whether the hit came from regex or AST.
That is important for compatibility.
Existing suppressions keep working when a matcher adds AST patterns.


### Example: AST-backed Go command injection

```toml
[[matcher]]
slug = "go-command-injection"
description = "exec.Command with dynamic shell or argv input"
noise_tier = "normal"
file_patterns = ["**/*.go"]
label = "exec.Command with dynamic command input"
[[matcher.ast_patterns]]
language = "go"
label = "exec.Command dynamic shell argument"
primary_capture = "@call"
snippet_capture = "@function"
prefilter_patterns = ["\\bexec\\.Command"]
query = '''
(
  function_declaration
    body: (block
      (expression_statement
        (call_expression
          function: (selector_expression
            operand: (identifier) @pkg
            field: (field_identifier) @method)
          arguments: (argument_list
            (_) 
            (_) 
            [
              (binary_expression) @dynamic
              (identifier) @dynamic
            ])))*) 
) @function
(#eq? @pkg "exec")
(#match? @method "^(Command|CommandContext)$")
'''

```

This replaces the current regex in `internal/scanner/matchers/go.toml:56`
and `internal/scanner/matchers/go.toml:57` only after benchmark proof.
During rollout it can coexist with the regex and be compared in the
bench harness.


### Example: AST-backed dangerous HTML

```toml
[[matcher]]
slug = "dangerous-html"
description = "Untrusted HTML written directly to DOM / response"
noise_tier = "normal"
file_patterns = ["**/*.ts", "**/*.tsx", "**/*.js", "**/*.jsx", "**/*.vue", "**/*.svelte"]
exclude_path_patterns = ["\\.(test|spec)\\.[jt]sx?$", "node_modules/"]
patterns = [
  "(?i)\\.innerHTML\\s*=\\s*[^;]*(?:req|input|user|body|params)",
  "(?i)\\bv-html\\s*=",
  "(?i)@@\\{",
]
label = "untrusted HTML injection into DOM"
[[matcher.ast_patterns]]
language = "tsx"
label = "React dangerouslySetInnerHTML"
primary_capture = "@attribute"
snippet_capture = "@attribute"
prefilter_patterns = ["dangerouslySetInnerHTML"]
query = '''
(
  jsx_attribute
    name: (property_identifier) @attr
    value: (jsx_expression
      (object
        (pair
          key: (property_identifier) @html_key
          value: (_) @html_value)))
) @attribute
(#eq? @attr "dangerouslySetInnerHTML")
(#eq? @html_key "__html")
'''
[[matcher.ast_patterns]]
language = "jsx"
label = "React dangerouslySetInnerHTML"
primary_capture = "@attribute"
snippet_capture = "@attribute"
prefilter_patterns = ["dangerouslySetInnerHTML"]
query = '''
(
  jsx_attribute
    name: (property_identifier) @attr
    value: (jsx_expression
      (object
        (pair
          key: (property_identifier) @html_key
          value: (_) @html_value)))
) @attribute
(#eq? @attr "dangerouslySetInnerHTML")
(#eq? @html_key "__html")
'''

```

The regex remains for `.innerHTML`, Vue, Svelte, and legacy syntaxes.
The React-specific AST pattern narrows the TSX and JSX case.


### Why not top-level `[[ast_matcher]]`
A separate top-level table looks clean at first.
It is rejected because the current registry is slug-centric.
`internal/scanner/registry.go:23` says the registry holds active
matchers keyed by slug.
`internal/scanner/registry.go:98` registers one matcher by slug.
`internal/scanner/registry.go:108` returns matchers in registration
order.
Creating `[[ast_matcher]]` would require either two registries or a
merge step by slug.
It would also force authors to duplicate description, noise tier,
requirements, and file globs.
Nested AST patterns keep one slug as one product concept.


### Why OR semantics
OR semantics preserve the current candidate mental model.
Every regex pattern today can independently emit a candidate.
Every AST pattern should do the same.
AND semantics are tempting for "regex prefilter plus AST confirmation."
They are rejected at the matcher level because they would silently
change what existing `patterns` means.
Use `prefilter_patterns` when the intent is prefiltering.
Use `patterns` when the intent is candidate emission.

## 5. The `Matcher.Match` Interface
Decision: keep the existing `Matcher.Match(content, filePath string)`
method for regex matching.
Add an internal AST path beside it.
Do not change `core.CandidateMatch`.
Do not change `FileRecord`.
Do not change processor input.
The public surface of the scanner remains the candidate list.
The internal scanner package can change.


### Current contract
The current method is not a Go interface type.
It is a concrete method on `*Matcher`.
`internal/scanner/matcher.go:58` defines `Matcher`.
`internal/scanner/matcher.go:78` defines `Match`.
Tests call it directly.
`internal/scanner/matcher_precision_test.go:21` calls `m.Match`.
`internal/scanner/matcher_precision_test.go:30` calls `m.Match`.
Keeping this method avoids unnecessary churn in existing tests.


### New internal contract
Introduce an internal package, likely `internal/scanner/ast`.
It should define:

```go
type Language string
type Tree interface {
    Language() Language
    FilePath() string
    Content() string
    RootRange() Range
}
type Query interface {
    Language() Language
    Execute(tree Tree) ([]QueryMatch, error)
}
type QueryMatch struct {
    Captures map[string]Node
}
type Node interface {
    Range() Range
    Text() string
}

```

The exact names can change in implementation.
The constraints cannot:
- AST matching must be internal to `internal/scanner`.
- AST matching must produce `core.CandidateMatch`.
- AST matching must not leak parser-specific tree types into `core`.
- AST matching must not alter persisted JSON.
`Matcher` gains methods like:

```go
func (m *Matcher) HasASTPatterns() bool
func (m *Matcher) ASTLanguages() []ast.Language
func (m *Matcher) MatchAST(tree ast.Tree, filePath string) []core.CandidateMatch

```

`MatchAST` should apply:
- Compiled AST queries.
- Snippet construction from source lines.
- `suppress_patterns`.
- Candidate deduplication within the matcher.
The existing `Match` method should keep applying:
- `exclude_path_patterns`.
- `require_content`.
- Regex `patterns`.
- `suppress_patterns`.
- Snippet construction.
Implementation may factor shared gate and snippet code into helpers.
That is an internal refactor.


### Runtime routing
The scan runtime should do this per file:
1. Read bytes.
2. Normalize CRLF to LF, as today at `internal/scanner/scan.go:93`.
3. Determine language from extension.
4. Build the candidate matcher list using active gates and file globs.
5. Run regex candidate patterns exactly as today.
6. Determine whether any AST pattern is eligible for this file.
7. If no AST pattern is eligible, do not initialize a parser and do not
   parse.
8. If AST patterns are eligible, evaluate `prefilter_patterns`.
9. If no eligible AST pattern passes its prefilter, do not parse.
10. Parse once.
11. Run all eligible AST queries against the parsed tree.
12. Merge candidates.
13. Deduplicate candidates.
14. Upsert the `FileRecord` exactly as today.
The routing belongs in `runMatchers` or a replacement helper.
`internal/scanner/scan.go:244` is the current natural seam.
The implementation should probably replace it with:

```go
runMatchers(reg, active, content, rel, astRuntime)

```

or a scanner struct that owns the registry and AST runtime.
Do not pass AST runtime into `core`.
Do not pass AST runtime into `processor`.


### What happens when a matcher has both regex and AST
Both paths run if both are eligible.
Candidates are unioned.
Duplicate candidates are removed by slug, matched pattern, and line
numbers, matching `internal/scanner/scan.go:310`.
AST candidates should set `MatchedPattern` to the AST pattern label.
If an AST and regex candidate share the same label and line, they
collapse into one record.
This is acceptable and useful during migration.
If a matcher author wants to compare regex and AST outputs separately,
they should use different labels temporarily.


### Public surface
No public CLI flag is required for the first AST release.
No JSON schema change is required.
No processor prompt change is required to consume AST candidates.
The processor already sees slug, lines, snippet, and matched pattern.
However, prompt guidance should be updated in lockstep with the agent
work described in section 10.
The bounded-patch proposer currently only knows regex TOML fields.
`internal/processor/agent_proposer.go:53` restricts decisions to
`suppress_pattern`, `require_content`, `file_patterns`,
`requires_tech`, and `needs-engine-feature`.
`internal/processor/prompts/agent.md:5` documents the same list.
Once AST lands, the agent must know whether it may propose
`ast_patterns`.
Until that prompt/schema is updated, the agent should continue to use
`needs-engine-feature` for AST-needed changes.

## 6. Performance and Caching
Decision: AST parsing is strictly demand-driven.
Regex-only users must pay near-zero AST cost.
The scanner should not initialize grammar modules unless at least one
active matcher contains an AST pattern.
The scanner should not parse a file unless at least one active,
glob-matching AST pattern targets the file's language and passes its
optional prefilter.


### Expected per-file cost
For a Go file of about 500 LOC:
- Current text read and normalization: unchanged.
- Current regex path: unchanged.
- `go/parser` reference benchmark: about 0.29 ms and 279 KB allocated.
- Expected tree-sitter WASM parse budget: 1.0 to 2.0 ms.
- Expected query execution for 10 to 20 AST patterns: 0.2 to 1.0 ms.
- Total AST-added cost for an eligible 500 LOC Go file: 1.2 to 3.0 ms.
The implementation must measure this with the actual wazero runtime and
grammar artifacts.
The acceptance target for the implementation issue is:
- p50 under 2 ms for a 500 LOC Go file with 10 AST patterns.
- p95 under 5 ms for a 500 LOC Go file with 10 AST patterns.
- p50 under 4 ms for a 500 LOC TSX file with 10 AST patterns.
- p95 under 10 ms for a 500 LOC TSX file with 10 AST patterns.
These are scanner budgets, not security-theory budgets.
If a grammar misses them badly, that language should not graduate from
experimental.


### Cost with zero AST matchers
When the matcher pack has zero active AST matchers:
- Do not construct the AST runtime.
- Do not load WASM modules.
- Do not compile AST queries.
- Do not allocate per-file AST planning structures.
- Do not branch per matcher beyond a single registry-level boolean.
The overhead target is less than 1 percent on `bench/tasks`.
On the current benchmark this should be lost in noise.
The implementation should add a benchmark that runs the current bundled
pack with AST disabled and compares it to the pre-AST baseline.


### Cost with AST matchers present but irrelevant
If AST matchers exist but no active matcher targets a file's language,
the file should not parse.
If AST matchers exist but file globs do not match, the file should not
parse.
If AST matchers exist but `require_content` fails, the file should not
parse.
If AST matchers exist and `prefilter_patterns` are configured but none
match, the file should not parse.
This matters because a repository can contain generated code, vendored
code, and many languages not covered by the AST rollout.


### Cache invalidation
There are two cache layers.
Layer 1 is an in-run parse cache.
Layer 2 is the future hash-based scan cache in issue 32.
The in-run parse cache stores parsed trees by:
- Project-relative file path.
- File hash.
- Language.
- Grammar version.
The file hash should use the same content hash already written to
`FileRecord.FileHash`.
`internal/scanner/scan.go:274` computes `core.FileHashHex`.
`internal/scanner/scan.go:294` stores it on the record.
`internal/core/types.go:261` persists it.
The grammar version must include:
- deepsec version or matcher-engine version.
- tree-sitter ABI version.
- grammar package name.
- grammar package version or embedded checksum.
If any of those change, a parsed tree is invalid.
Issue 32 says unchanged file hashes should skip matcher execution.
The AST implementation should integrate with that design but not block
on it.
When issue 32 lands:
- If `FileRecord.FileHash` matches and matcher-pack fingerprint matches,
  skip regex and AST execution.
- If `FileRecord.FileHash` matches but matcher-pack fingerprint differs,
  re-run matchers.
- If `--force-rescan` is set, re-run matchers.
- If a file is re-run and AST is eligible, parse from content as usual.
Do not persist tree binaries in `data/`.
The on-disk data layout is intentionally wire-compatible with the
original TypeScript implementation.
`docs/data-layout.md:3` documents that compatibility.
Tree binary persistence would break that simplicity and couple data to
grammar versions.


### Memory cap
Do not hold every tree in RAM.
A 100k-file scan cannot retain all ASTs.
Use an in-run weighted LRU cache.
The default cap is 128 MiB.
The weight for a tree is:
- Source length.
- Parser-reported tree byte size if available.
- Otherwise `4 * source length` as a conservative estimate.
The cache key is `(language, fileHash, grammarVersion)`.
The cache value is the parsed tree plus line index.
The scanner normally processes each file once, so the LRU mainly helps
when multiple AST matcher groups request the same tree or when future
diff/retry paths revisit a file inside one run.
If the LRU is full:
- Evict least recently used trees.
- Never evict a tree while it is being queried.
- Do not fail the scan just because caching is ineffective.
Expose internal counters in scan outcome later:
- `astFilesParsed`.
- `astParseCacheHits`.
- `astParseCacheMisses`.
- `astParseErrors`.
- `astQueryErrors`.
Those counters do not need to land in `RunMeta` in the first
implementation.
They should appear in verbose scan logs or benchmark output first.


### Parse errors
Malformed source should not fail the whole scan.
Tree-sitter can produce error nodes.
The AST runtime should run queries on recoverable trees.
If parsing fails catastrophically, record an internal parse error counter
and continue with regex candidates for that file.
The scanner currently skips unreadable files.
`internal/scanner/scan.go:89` reads the file.
`internal/scanner/scan.go:90` continues on read error.
AST parse failure should be no more fatal than read failure.
Bundled matcher query compile errors are different.
Those should fail startup because the pack is broken.

## 7. Language Rollout Order
Decision: Go first, but through tree-sitter WASM rather than
`go/parser`.
The order is:
1. Go.
2. TypeScript, TSX, JavaScript, JSX.
3. Python.
4. Rust.
5. C and C++ only after a separate scoping issue.


### Phase 1: Go
Go goes first because:
- It is the implementation language of deepsec.
- The repo already has Go fixtures.
- The current benchmark has Go route false positives.
- `go-http-handler` hit `needs-engine-feature`.
- Go syntax is comparatively stable.
- Go imports and selectors make good first AST query examples.
Minimum AST matcher set:
- `go-command-injection`.
- `go-http-handler` with direct sink-in-handler shapes.
- `go-ssrf`.
- `go-sql-raw`.
- `tls-skip-verification` for Go composite literals.
Success metric:
- Remove all 4 current `go-http-handler` false positives from
  `bench/tasks/go-vulnerable-cli`.
- Preserve recall for `go-cmd-001`, `go-path-001`, `go-crypto-001`, and
  `go-ssrf-001`.
- Do not increase total candidates on the Go task.
- Keep AST-added p95 under 5 ms for 500 LOC Go files.


### Phase 2: TypeScript and JavaScript
TS/JS goes second because:
- The current core matchers target TS/JS heavily.
- TSX is needed for `dangerous-html`.
- The benchmark has command injection, SSRF, path traversal, SQL, crypto,
  random, and open redirect examples in TypeScript.
- Many users will scan web apps first.
Minimum AST matcher set:
- `dangerous-html` for JSX and `React.createElement`.
- `command-injection` for Node `child_process` APIs.
- `sql-injection-string-concat` for known SQL API calls.
- `ssrf` for direct request-derived `fetch` and HTTP client calls.
- `path-traversal` for direct request-derived FS calls.
- `open-redirect` for direct `res.redirect(req...)`.
Success metric:
- Remove the current SQL false positive on the TS command execution file.
- Preserve all TS benchmark true positives.
- Do not regress `dangerous-html` tests at
  `internal/scanner/matcher_precision_test.go:94`.
- Add at least three TSX AST regression cases for dangerous HTML.


### Phase 3: Python
Python goes third because:
- The current benchmark has a Python SQL false negative.
- `flask-route` hit `needs-engine-feature`.
- Python AST shapes for decorators and calls are straightforward.
- Tree-sitter-python quality is good enough for this use case.
Minimum AST matcher set:
- `flask-route` with direct sink-in-route shapes.
- `python-eval-exec` excluding `ast.literal_eval`.
- `sql-injection-string-concat` for f-strings and `%` formatting inside
  execute calls.
- `ssrf` for direct `requests.get(request.args...)`.
- `python-pickle-load` with `yaml.load` loader argument handling.
Success metric:
- Remove all 6 current `flask-route` false positives as route-only
  candidates.
- Recover `py-sqli-001`.
- Preserve `py-ssrf-001` and `py-eval-001`.
- Preserve the decoys in `bench/tasks/py-vulnerable-flask/answer.yaml`.


### Phase 4: Rust
Rust goes fourth.
It is valuable but less urgent than Go, TS, and Python in the current
bench.
Minimum AST matcher set:
- `rust-cmd-injection`.
- `rust-unsafe-block`.
- Axum handler direct request-to-sink shapes.
- Actix handler direct request-to-sink shapes.
Success metric:
- Add a Rust benchmark task before enabling bundled Rust AST matchers.
- Demonstrate at least one false-positive reduction and one true
  positive preservation.


### Phase 5: C and C++
C and C++ are future work.
They should not be included in RFC 001 implementation.
They are relevant for deeper native-code audits, but the grammar,
preprocessor, compile-command, and macro issues deserve separate design.

## 8. Migration Plan for Existing Matchers
The current 82 matchers stay regex-only at first.
Do not mass-convert.
Do not convert secrets.
Do not convert Dockerfile, Terraform, Kubernetes, or GitHub Actions
matchers in this RFC.
The first AST work should target slugs that currently demonstrate
structural false positives or false negatives.


### Migration order
1. `go-http-handler`.
2. `flask-route`.
3. `sql-injection-string-concat`.
4. `go-command-injection`.
5. `command-injection`.
6. `dangerous-html`.
7. `go-ssrf`.
8. `ssrf`.
9. `path-traversal`.
10. `python-eval-exec`.
11. `tls-skip-verification`.
12. `open-redirect`.


### Work estimate by slug
`go-http-handler`: 1 to 2 days.
This is not a route matcher anymore.
It becomes a handler-with-interesting-body matcher.
The implementation needs Go handler queries and benchmark rewrite of
route-only expectations.
`flask-route`: 1 to 2 days.
It needs decorator matching and direct sink-in-function queries.
It should avoid claiming auth absence.
`sql-injection-string-concat`: 2 to 4 days.
This crosses TS, Python, Go, and possibly Ruby.
Start with TS and Python direct call shapes.
Do not attempt ORM semantics.
`go-command-injection`: 1 day.
Selector calls and argument expressions are straightforward.
Add hardcoded argv decoy coverage.
`command-injection`: 2 to 3 days.
JavaScript child-process APIs have multiple call forms.
Separate shell APIs from `execFile` constant argv.
`dangerous-html`: 1 to 2 days.
JSX attribute and `React.createElement` object property matching are
clear.
Vue and Svelte remain regex until their AST grammars are deliberately
added.
`go-ssrf`: 1 day.
Match direct request-derived `http.Get`, `http.Post`, and
`http.NewRequest`.
`ssrf`: 2 to 3 days.
TS and Python direct request-to-client call patterns.
Avoid URL validation claims.
`path-traversal`: 2 to 3 days.
TS, Python, and Go direct request-to-file API patterns.
Avoid sanitizer claims.
`python-eval-exec`: 0.5 to 1 day.
Mostly structural exclusions and direct call matching.
`tls-skip-verification`: 1 to 2 days.
Object/composite literal matching across JS and Go.
`open-redirect`: 1 to 2 days.
Direct redirect calls only.
Allow-list validation remains future dataflow/semantic work.


### Migration mechanics
For each slug:
1. Add AST patterns beside existing regex patterns.
2. Use distinct labels for AST patterns during the bake-off.
3. Run `go run ./cmd/benchsec review --slug <slug>`.
4. Add regression cases for fixed false positives.
5. Compare candidate counts.
6. Remove or narrow regex only after AST proves better.
The human review loop already supports slug-level review.
`docs/matcher-review.md:3` says it works one matcher slug at a time.
`docs/matcher-review.md:93` shows false positives and false negatives.
`docs/matcher-review.md:96` shows before/after delta.
AST migration should reuse that path.

## 9. Testing Strategy
Decision: preserve all existing regex matcher tests and add a separate
AST-focused test suite.
Do not replace `matcher_precision_test.go`.
Add `ast_precision_test.go` or an `internal/scanner/ast` test package.


### Existing tests stay
`internal/scanner/matcher_precision_test.go` should continue to compile
the bundled pack.
Existing `assertHits` and `assertNoHits` should continue to call
`Matcher.Match`.
That protects regex-only behavior.
It also keeps custom matcher authors from being forced into AST
dependencies.


### New unit tests
Add unit tests for:
- AST TOML decoding.
- AST query compile errors.
- Unsupported predicate rejection.
- Language mismatch.
- Prefilter skipping parse.
- Regex-only matcher incurs no AST runtime initialization.
- Matcher with both regex and AST emits unioned candidates.
- Duplicate regex and AST candidate deduplication.
- `suppress_patterns` suppressing AST candidates.
- Snippet capture fallback.
- Parse error handling.


### Golden tests
Do not commit serialized tree representations.
Tree binary formats are grammar and runtime implementation details.
Instead, commit source fixtures and expected candidate records.
For example:

```go
func TestASTGoCommandInjectionSkipsConstantArgv(t *testing.T) {
    content := `package main
import "os/exec"
func ok() { exec.Command("/usr/bin/uptime").Run() }
`
    hits := runASTMatcher(t, "go-command-injection", content, "main.go")
    require.Empty(t, hits)
}

```

This mirrors the current regex tests.
`internal/scanner/matcher_precision_test.go:64` already tests that
static Python argv does not fire for `command-injection`.
AST tests should add the equivalent Go and TS cases.


### Scanner integration tests
Add scan-level tests that use `scanner.Scan` or `ScanFiles`.
The test should create a temporary project, write source files, run a
registry with AST matchers, and read `FileRecord.Candidates`.
It should assert the persisted JSON shape is unchanged.
This is important because the processor and reports consume
`FileRecord`.


### Benchmark tests
Add Go benchmarks for:
- Regex-only scan of current fixtures.
- AST runtime initialized but no eligible files.
- AST parse and query of 500 LOC Go.
- AST parse and query of 500 LOC TSX.
- AST parse-cache hit.
- AST parse-cache miss.
The implementation PR should report:
- ns/op.
- B/op.
- allocs/op.
- binary size delta.


### Bench harness updates
The bench harness should not need schema changes.
`bench/README.md:3` says the scorer calls `scanner.Scan`.
`bench/README.md:5` says it reads emitted `FileRecord.Candidates`.
AST candidates are still candidates.
However, benchmark reports should add optional counters once available:
- AST parses.
- AST parse errors.
- AST query errors.
- AST skipped by prefilter.
The answer key schema remains unchanged.
`bench/README.md:121` says candidate matching is file, slug, and line
tolerance.
AST candidates should obey the same line tolerance rules.


### Linter updates
`benchsec lint-matchers` currently checks regex issues.
`bench/README.md:220` lists linter checks.
Extend it to check:
- Unknown AST language.
- Empty AST query.
- Unsupported tree-sitter predicate.
- Missing `primary_capture` when query has no `@match`.
- `patterns` empty and `ast_patterns` empty.
- AST pattern language inconsistent with `file_patterns`.
- AST matcher without a prefilter when it targets very broad globs and
  noise tier is `noisy`.
Linter failures for bundled matchers should be hard errors.
For custom matchers, the same load errors should be returned to the
user.

## 10. Risk Register


### Risk 1: WASM grammar quality varies
Tree-sitter grammars vary by language and by syntax vintage.
TypeScript and TSX syntax changes quickly.
If grammar support lags, queries may miss newer syntax or parse it into
unexpected nodes.
Mitigation:
- Pin grammar versions.
- Store grammar checksums in the binary.
- Add syntax fixtures for TSX, JSX, Go, and Python.
- Treat grammar upgrades like matcher-pack changes with benchmark runs.
- Keep regex fallback patterns during migration.


### Risk 2: Tree-sitter query gotchas
Tree-sitter queries are powerful but subtle.
Capture order, field names, anonymous nodes, and predicates can surprise
authors.
Mitigation:
- Support a small predicate subset first.
- Fail unknown predicates at compile time.
- Add `docs/writing-ast-matchers.md` in the implementation PR.
- Add `benchsec lint-matchers` AST validation.
- Require regression cases for every AST matcher conversion.


### Risk 3: Parser OOM or pathological source
The walker allows files up to 1 MiB.
`internal/scanner/walker.go:67` sets that cap.
Some generated files under 1 MiB can still be parser-hostile.
Mitigation:
- Keep the 1 MiB cap.
- Add per-file parse timeout or context cancellation.
- Recover from parser/runtime panics at the AST boundary.
- Count parse failures and continue with regex candidates.
- Do not parse if no AST matcher is eligible.


### Risk 4: Binary size growth
The current stripped binary is about 13.6 MB locally.
`README.md:32` advertises a distroless image around 20 MB.
Embedding too many grammars can erode that advantage.
Mitigation:
- Hard acceptance cap: binary delta <= 5 MB.
- Start with Go, TS/JS, TSX/JSX, and Python only.
- Defer Rust if size is tight.
- Compress embedded grammar bytes only if startup cost stays acceptable.
- Report binary size in the implementation PR.


### Risk 5: Regex-only users pay AST cost
If AST runtime initialization is global, every scan gets slower.
That would violate the current scanner's cheap first stage.
Mitigation:
- Registry-level `HasASTPatterns`.
- Lazy runtime initialization.
- Per-file eligibility planning before parse.
- Benchmark regex-only fixture scans before and after.
- Make zero-AST overhead target less than 1 percent.


### Risk 6: AST candidates confuse the processor
The processor expects snippets and line numbers, not parser metadata.
If AST snippets are too narrow or too broad, the LLM may perform worse.
Mitigation:
- Keep `core.CandidateMatch` unchanged.
- Use `snippet_capture` to choose function-level context when needed.
- Preserve `snippet_before` and `snippet_after`.
- Add processor replay fixtures after AST candidates exist.
- Update slug hints only when matcher labels change materially.


### Risk 7: The bounded-patch agent proposes invalid AST changes
Issue 17's agent currently has a strict patch schema.
`internal/processor/agent_proposer.go:53` does not permit AST patterns.
`internal/processor/prompts/agent.md:29` tells the model not to modify
`patterns`.
Once AST exists, the model will ask for it.
Mitigation:
- Keep `needs-engine-feature` as the only allowed AST deferral until the
  agent schema changes.
- File a follow-up for AST patch proposals.
- Update `internal/processor/prompts/agent.md` and `PatchSchema`
  together.
- Gate AST patches through the same bench and regression flow.


### Risk 8: Query labels fragment metrics
If AST and regex labels differ, candidate dedup and reports may show
separate entries for the same site.
Mitigation:
- During migration, use distinct labels deliberately for comparison.
- Before finalizing a slug, align labels to collapse equivalent hits.
- Keep candidate key behavior documented.
- Add tests for duplicate AST and regex candidates.


### Risk 9: Language detection by extension is too coarse
`internal/scanner/scan.go:340` maps extensions to language names.
TSX and JSX need different grammars from TS and JS.
Some files use unusual extensions.
Mitigation:
- Extend `langFor` to distinguish `.tsx` and `.jsx` for AST routing.
- Keep existing user-facing language stats stable unless needed.
- Allow explicit language in AST pattern.
- Skip AST when language is unknown.


### Risk 10: Dataflow expectations creep into AST matching
AST is not dataflow.
The pressure to reduce false positives can lead to overclaiming.
Mitigation:
- Name AST labels precisely: "dynamic command argument", not "confirmed
  command injection."
- Keep the processor as the finding confirmation stage.
- Document dataflow boundaries in matcher docs.
- Open a separate dataflow RFC if needed.

## 11. Rejected Alternatives
This section closes the main design space.


### Embedding: CGo native tree-sitter
Rejected despite speed.
Reason:
- Breaks `CGO_ENABLED=0`.
- Complicates release matrix.
- Weakens distroless/static deployment.
The decisive evidence is the current Dockerfile.
`Dockerfile:6` explicitly builds with CGo disabled.
`Dockerfile:8` runs from a static distroless base.


### Embedding: sidecar `tree-sitter` CLI
Rejected despite preserving a pure-Go deepsec binary.
Reason:
- Per-file process cost is too high.
- Operational dependency is awkward.
- Long-running sidecar adds more architecture than wazero.
The local lower-bound spawn cost was about 0.57 ms per process.
That cost alone is unacceptable at 100k files.


### Embedding: native parser per language
Rejected as the general strategy.
Reason:
- Good for Go only.
- No equivalent production-quality stdlib parsers for TSX, JSX, Python,
  and Rust in Go.
- Forces multiple authoring models.


### Embedding: hybrid Go-native plus WASM
Rejected as the most tempting alternative.
Reason:
- Creates two AST stacks immediately.
- Makes query documentation and agent patches harder.
- Optimizes before the bottleneck is proven.
The Go-native path remains plausible as a future invisible optimization.
It must not change TOML syntax if introduced later.


### Query language: custom deepsec DSL
Rejected despite authoring appeal.
Reason:
- Would require deepsec to own language design.
- Would require per-language compilers.
- Would hide tree-sitter power behind a partial abstraction.


### Query language: Semgrep-style patterns
Rejected despite familiarity.
Reason:
- Embedding Semgrep violates the Go-binary story.
- Reimplementing Semgrep creates a partial clone.
- Pattern semantics would be hard to keep honest.


### TOML shape: top-level `[[ast_matcher]]`
Rejected despite clean separation.
Reason:
- Duplicates slug metadata.
- Requires registry merge logic.
- Makes one vulnerability concept live in two tables.
The existing registry is slug-centric at `internal/scanner/registry.go:23`.


### TOML semantics: regex AND AST
Rejected as matcher-level default.
Reason:
- Changes what `patterns` means.
- Makes existing author intuition wrong.
- Creates hidden candidate suppression.
Use `prefilter_patterns` for AST-only prefiltering.


### Interface: change `Matcher.Match` to require AST
Rejected.
Reason:
- Existing tests and custom mental model use text matching.
- Regex-only matchers should remain simple.
- AST is an additional internal path, not a replacement for text.


### Persistence: store AST trees on disk
Rejected.
Reason:
- Ties `data/` to grammar versions.
- Breaks the simple TypeScript-compatible wire format.
- Creates invalidation problems larger than parsing cost.
Use `FileRecord.FileHash` and future issue 32 scan caching instead.


### Caching: unbounded tree cache
Rejected.
Reason:
- 100k-file scans can exhaust memory.
- Most files are scanned once.
- A bounded LRU gives safety without overengineering.
Default cap: 128 MiB.

## 12. Open Questions and Future Work


### Exact grammar packaging
The implementation must choose the grammar build pipeline.
The RFC decision is "WASM grammars through wazero."
It does not prescribe whether grammar WASM files are generated by a
checked-in script, pulled from pinned modules, or stored as embedded
artifacts.
Recommendation:
- Pin grammar sources.
- Generate artifacts reproducibly.
- Commit checksums.
- Avoid checking in opaque generated files if `go generate` can produce
  them reliably in CI.


### Exact tree-sitter query API in Go
The Go ecosystem's tree-sitter WASM query API shape may constrain the
internal interfaces.
The implementation may need a thin adapter.
That is acceptable if TOML syntax stays stable.


### Query portability across grammar versions
Tree-sitter node names can change across grammar versions.
The mitigation is pinned grammars and query compile tests.
Future work could add a matcher-pack compatibility test matrix across
grammar upgrades.


### AST authoring docs
This RFC does not add `docs/writing-ast-matchers.md` because the user
asked for the RFC as the deliverable.
The implementation PR should add that doc.
It should mirror `docs/writing-matchers.md`:
- Minimal example.
- Schema.
- Query syntax.
- Predicate subset.
- Language-specific examples.
- Testing workflow.


### Agent AST patch proposals
The bounded-patch agent should not immediately write AST queries.
Tree-sitter queries are easier to get subtly wrong than regex
suppressions.
Recommended staged plan:
1. Let the agent continue returning `needs-engine-feature`.
2. Add AST evidence to the proposer context.
3. Permit AST proposals only behind a flag.
4. Require linter, bench, regression cases, and human review before
   commit.


### Dataflow
AST matching will expose the next ceiling quickly.
For example:

```go
term := r.URL.Query().Get("term")
cmd := buildGrep(term)
exec.Command("sh", "-c", cmd)

```

AST can match the call structure.
It cannot prove the interprocedural flow without dataflow analysis.
Recommendation:
- Do not smuggle dataflow into RFC 001.
- File a separate RFC after AST matchers land and bench evidence shows
  the remaining false positives or false negatives.


### Matcher-pack fingerprint
Issue 32 needs a matcher-pack fingerprint for cache correctness.
AST makes that more important.
The fingerprint should include:
- Matcher TOML bytes.
- Built-in matcher pack version.
- Extra matcher file bytes.
- AST grammar versions.
- AST query engine version.
This can land with issue 32 or with AST implementation if sequencing
demands it.


### Language stats
`internal/scanner/scan.go:340` currently maps `.ts` and `.tsx` to
`typescript`, and `.js` and `.jsx` to `javascript`.
AST routing may need `tsx` and `jsx`.
Open question:
- Should user-facing language stats split TSX/JSX?
- Or should only internal AST routing split them?
Recommendation:
- Keep user-facing stats as TypeScript and JavaScript for now.
- Split internally for parser selection.


### Vue and Svelte
`dangerous-html` currently targets Vue and Svelte.
RFC 001 does not add Vue or Svelte AST grammars.
Those regexes should remain.
Future work can add framework-specific parsers if the benchmark shows
enough value.


### Rust timing
Rust is valuable, but the initial benchmark does not force it.
If binary size or implementation time is tight, defer Rust.
Do not defer Go, TS/JS, TSX/JSX, or Python.


### C and C++ timing
C and C++ should wait.
The preprocessor and compile-command context are a different problem.
Adding tree-sitter-c without addressing macros would create a false
sense of precision.


### SARIF and reports
No SARIF changes are required for AST candidates.
Reports consume findings, not raw parser metadata.
If future reports want to show "matched by AST", that should be derived
from `matchedPattern` labels or a future optional candidate metadata
field.
Do not add that metadata in RFC 001.

## Implementation Acceptance Checklist
This section is not implementation, but it defines what the next PR must
prove.
- Existing matcher TOML loads unchanged.
- Existing regex-only tests pass unchanged.
- Current `core.CandidateMatch` JSON shape is unchanged.
- Current `FileRecord` JSON shape is unchanged.
- Binary size delta is <= 5 MB.
- Cross-compilation remains pure Go.
- Distroless Docker build remains static.
- Regex-only scan overhead is under 1 percent.
- Go AST p95 for 500 LOC and 10 AST patterns is under 5 ms.
- TSX AST p95 for 500 LOC and 10 AST patterns is under 10 ms.
- `go-http-handler`, `flask-route`, and `sql-injection-string-concat`
  have AST migration examples or explicit implementation follow-ups.
- The bounded-patch agent schema remains conservative until updated.

## Final Recommendation
Build AST matching as a demand-driven tree-sitter WASM subsystem behind
the existing scanner candidate contract.
Keep matcher identity slug-centric.
Add `[[matcher.ast_patterns]]` to TOML.
Use tree-sitter S-expression queries.
Run regex and AST patterns as OR-producing candidate sources.
Parse only when an active AST matcher can use the file.
Do not persist trees.
Do not introduce CGo.
Do not introduce a Go-native special case in the first release.
Do not pretend AST is dataflow.
