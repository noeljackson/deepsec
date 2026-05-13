# Writing AST Matchers

AST matchers are nested under the existing `[[matcher]]` TOML table.
They emit the same scanner candidates as regex matchers: slug, line
numbers, snippet, and matched pattern label.

## Schema

```toml
[[matcher.ast_patterns]]
language = "go"
label = "exec.Command dynamic argument"
primary_capture = "@call"
snippet_capture = "@call"
prefilter_patterns = ["\\bexec\\.Command"]
query = '''
(
  call_expression
    function: (selector_expression
      operand: (identifier) @pkg
      field: (field_identifier) @method)
) @call
(#eq? @pkg "exec")
(#match? @method "^(Command|CommandContext)$")
'''
```

Supported Phase 1 languages are `go`, `typescript`, `tsx`,
`javascript`, `jsx`, and `python`.

`primary_capture` selects the AST node that marks the candidate line.
It defaults to `@match`. `snippet_capture` selects the node used for
snippet construction and defaults to `primary_capture`.

## Query Syntax

Queries use tree-sitter S-expression query syntax. The initial predicate
subset is deliberately small:

- `#eq?`
- `#match?`
- `#not-eq?`
- `#not-match?`

Unsupported predicates fail matcher compilation.

## Capture Conventions

Use stable capture names so review output is easy to read:

- `@match` for the candidate node when no narrower name fits.
- `@call` for sink calls.
- `@function` for route or handler bodies.
- `@callee`, `@method`, and `@sink` for callable names.
- `@source` for request-derived values.

## Prefilters

`prefilter_patterns` are RE2 regexes used only to decide whether a file
is worth parsing. They do not emit candidates. Parent `patterns` still
emit regex candidates, so do not use them as AST prefilters.

## Worked Examples

Go command execution:

```scheme
(
  call_expression
    function: (selector_expression
      operand: (identifier) @pkg
      field: (field_identifier) @method)
    arguments: (argument_list (binary_expression) @dynamic_arg)
) @call
(#eq? @pkg "exec")
(#match? @method "^(Command|CommandContext)$")
```

React dangerous HTML:

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

## Local Testing

Run:

```bash
go test ./internal/scanner/...
go run ./cmd/benchsec lint-matchers
```

When the tree-sitter CLI is available, test the query against a fixture
with the pinned grammar before committing it. The scanner linter checks
TOML shape, supported predicates, captures, and prefilter regexes; it
does not replace fixture tests.

