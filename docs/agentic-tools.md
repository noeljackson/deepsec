# Agentic Investigation Tools

`deepsec process --tools` enables a multi-turn investigation mode for
providers with tool-use support. The default `process` path is unchanged:
without `--tools`, each batch is still one model request with the existing
structured `report_findings` response.

Agentic mode gives the investigator five read-only tools scoped to the
configured project root:

| Tool | Purpose | Bounds |
|---|---|---|
| `read_file(path, start_line?, end_line?)` | Read a project-relative file or line slice. | Rejects paths outside the project; max 16 KiB returned. |
| `grep(pattern, glob?, max_results?)` | Search source files line by line with a Go regex. | Honors `.gitignore` through the scanner walker; max 100 result lines, 2,000 scanned files, 16 KiB returned. |
| `find_callers(symbol, glob?)` | Find naive function-call references matching `<symbol>\s*\(`. | Same search caps as `grep`. |
| `read_neighbors(path, line, radius)` | Read a context window around a candidate line. | Radius capped at 80; max 16 KiB returned. |
| `git_blame(path, line)` | Return commit, author, author time, and summary for one line. | Rejects paths outside the project; returns one line of blame metadata. |

Use `--tools` when candidate exploitability depends on context outside the
snippet: route registration, middleware, upstream sanitization, helper
wrappers, authorization gates, or dataflow through nearby files. It costs more
and takes longer because each tool step is another model round trip.

```bash
deepsec process --project-id myproj --tools --max-turns 8 --max-cost-usd 2
```

`--max-turns` caps model turns per investigation. `--max-cost-usd` is checked
by the process runner and by the tool loop so a batch cannot spin indefinitely.
If the model returns plain text instead of a tool call or `report_findings`,
deepsec records the batch as a refusal.
