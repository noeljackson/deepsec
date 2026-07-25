package tools

import (
	"bufio"
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/noeljackson/deepsec/internal/core"
	"github.com/noeljackson/deepsec/internal/scanner"
)

const (
	MaxReadBytes    = 16 * 1024
	MaxResultLines  = 100
	MaxFilesScanned = 256
	MaxGrepBytes    = 8 * 1024 * 1024
	toolTimeout     = 5 * time.Second
)

// Tool is a repo-scoped read-only function the investigator model can call.
type Tool interface {
	Name() string
	Schema() json.RawMessage
	Run(ctx context.Context, args json.RawMessage) (string, error)
}

// New returns the five investigation tools bound to projectRoot.
func New(projectRoot string) []Tool {
	return []Tool{
		readFileTool{root: projectRoot},
		grepTool{root: projectRoot},
		findCallersTool{root: projectRoot},
		readNeighborsTool{root: projectRoot},
		gitBlameTool{root: projectRoot},
	}
}

func ByName(ts []Tool) map[string]Tool {
	out := make(map[string]Tool, len(ts))
	for _, t := range ts {
		out[t.Name()] = t
	}
	return out
}

type readFileTool struct{ root string }

func (readFileTool) Name() string { return "read_file" }
func (readFileTool) Schema() json.RawMessage {
	return mustSchema(map[string]any{
		"type":                 "object",
		"required":             []string{"path"},
		"additionalProperties": false,
		"properties": map[string]any{
			"path":       map[string]any{"type": "string", "description": "Project-relative file path."},
			"start_line": map[string]any{"type": "integer", "minimum": 1},
			"end_line":   map[string]any{"type": "integer", "minimum": 1},
		},
	})
}
func (t readFileTool) Run(ctx context.Context, args json.RawMessage) (string, error) {
	var in struct {
		Path      string `json:"path"`
		StartLine int    `json:"start_line"`
		EndLine   int    `json:"end_line"`
	}
	if err := json.Unmarshal(args, &in); err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	abs, rel, err := safePath(t.root, in.Path)
	if err != nil {
		return "", err
	}
	body, truncated, err := readBoundedFile(abs, MaxReadBytes)
	if err != nil {
		return "", err
	}
	return formatLineSlice(rel, body, in.StartLine, in.EndLine, MaxReadBytes, truncated), nil
}

type grepTool struct{ root string }

func (grepTool) Name() string { return "grep" }
func (grepTool) Schema() json.RawMessage {
	return mustSchema(map[string]any{
		"type":                 "object",
		"required":             []string{"pattern"},
		"additionalProperties": false,
		"properties": map[string]any{
			"pattern":     map[string]any{"type": "string", "description": "Go regular expression searched line-by-line."},
			"glob":        map[string]any{"type": "string", "description": "Optional doublestar glob such as **/*.ts."},
			"max_results": map[string]any{"type": "integer", "minimum": 1, "maximum": MaxResultLines},
		},
	})
}
func (t grepTool) Run(ctx context.Context, args json.RawMessage) (string, error) {
	var in struct {
		Pattern    string `json:"pattern"`
		Glob       string `json:"glob"`
		MaxResults int    `json:"max_results"`
	}
	if err := json.Unmarshal(args, &in); err != nil {
		return "", err
	}
	return grepProject(ctx, t.root, in.Pattern, in.Glob, boundMax(in.MaxResults), MaxReadBytes)
}

type findCallersTool struct{ root string }

func (findCallersTool) Name() string { return "find_callers" }
func (findCallersTool) Schema() json.RawMessage {
	return mustSchema(map[string]any{
		"type":                 "object",
		"required":             []string{"symbol"},
		"additionalProperties": false,
		"properties": map[string]any{
			"symbol": map[string]any{"type": "string", "description": "Function or method name to search for as a call."},
			"glob":   map[string]any{"type": "string", "description": "Optional doublestar glob such as **/*.go."},
		},
	})
}
func (t findCallersTool) Run(ctx context.Context, args json.RawMessage) (string, error) {
	var in struct {
		Symbol string `json:"symbol"`
		Glob   string `json:"glob"`
	}
	if err := json.Unmarshal(args, &in); err != nil {
		return "", err
	}
	if in.Symbol == "" {
		return "", errors.New("symbol is required")
	}
	pattern := `\b` + regexp.QuoteMeta(in.Symbol) + `\s*\(`
	return grepProject(ctx, t.root, pattern, in.Glob, MaxResultLines, MaxReadBytes)
}

type readNeighborsTool struct{ root string }

func (readNeighborsTool) Name() string { return "read_neighbors" }
func (readNeighborsTool) Schema() json.RawMessage {
	return mustSchema(map[string]any{
		"type":                 "object",
		"required":             []string{"path", "line", "radius"},
		"additionalProperties": false,
		"properties": map[string]any{
			"path":   map[string]any{"type": "string"},
			"line":   map[string]any{"type": "integer", "minimum": 1},
			"radius": map[string]any{"type": "integer", "minimum": 0, "maximum": 80},
		},
	})
}
func (t readNeighborsTool) Run(ctx context.Context, args json.RawMessage) (string, error) {
	var in struct {
		Path   string `json:"path"`
		Line   int    `json:"line"`
		Radius int    `json:"radius"`
	}
	if err := json.Unmarshal(args, &in); err != nil {
		return "", err
	}
	if err := ctx.Err(); err != nil {
		return "", err
	}
	if in.Line < 1 {
		return "", errors.New("line must be >= 1")
	}
	if in.Radius < 0 {
		return "", errors.New("radius must be >= 0")
	}
	if in.Radius > 80 {
		in.Radius = 80
	}
	abs, rel, err := safePath(t.root, in.Path)
	if err != nil {
		return "", err
	}
	body, truncated, err := readBoundedFile(abs, MaxReadBytes)
	if err != nil {
		return "", err
	}
	return formatLineSlice(rel, body, in.Line-in.Radius, in.Line+in.Radius, MaxReadBytes, truncated), nil
}

type gitBlameTool struct{ root string }

func (gitBlameTool) Name() string { return "git_blame" }
func (gitBlameTool) Schema() json.RawMessage {
	return mustSchema(map[string]any{
		"type":                 "object",
		"required":             []string{"path", "line"},
		"additionalProperties": false,
		"properties": map[string]any{
			"path": map[string]any{"type": "string"},
			"line": map[string]any{"type": "integer", "minimum": 1},
		},
	})
}
func (t gitBlameTool) Run(ctx context.Context, args json.RawMessage) (string, error) {
	var in struct {
		Path string `json:"path"`
		Line int    `json:"line"`
	}
	if err := json.Unmarshal(args, &in); err != nil {
		return "", err
	}
	if in.Line < 1 {
		return "", errors.New("line must be >= 1")
	}
	_, rel, err := safePath(t.root, in.Path)
	if err != nil {
		return "", err
	}
	line := strconv.Itoa(in.Line)
	timeoutCtx, cancel := context.WithTimeout(ctx, toolTimeout)
	defer cancel()
	cmd := exec.CommandContext(timeoutCtx, "git", "-C", t.root, "blame", "--line-porcelain", "-L", line+","+line, "--", rel)
	body, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git blame unavailable for %s:%d", rel, in.Line)
	}
	return formatBlame(rel, in.Line, body), nil
}

func grepProject(ctx context.Context, root, pattern, glob string, maxResults, maxBytes int) (string, error) {
	if pattern == "" {
		return "", errors.New("pattern is required")
	}
	re, err := regexp.Compile(pattern)
	if err != nil {
		return "", err
	}
	files, err := scanner.WalkProject(root)
	if err != nil {
		return "", err
	}
	sort.Strings(files)
	var out bytes.Buffer
	results, scanned := 0, 0
	scannedBytes := int64(0)
	truncated := false
	for _, rel := range files {
		if err := ctx.Err(); err != nil {
			return "", err
		}
		if glob != "" {
			ok, _ := doublestar.PathMatch(glob, rel)
			if !ok {
				continue
			}
		}
		abs := filepath.Join(root, filepath.FromSlash(rel))
		info, err := os.Stat(abs)
		if err != nil {
			continue
		}
		if scannedBytes+info.Size() > MaxGrepBytes {
			truncated = true
			break
		}
		scannedBytes += info.Size()
		scanned++
		if scanned > MaxFilesScanned {
			truncated = true
			break
		}
		hit, err := grepFile(abs, rel, re, &out, &results, maxResults, maxBytes)
		if err != nil {
			continue
		}
		if hit {
			truncated = true
			break
		}
	}
	if results == 0 {
		return "no matches", nil
	}
	if truncated {
		out.WriteString("results truncated - refine your query\n")
	}
	return out.String(), nil
}

func grepFile(abs, rel string, re *regexp.Regexp, out *bytes.Buffer, results *int, maxResults, maxBytes int) (bool, error) {
	f, err := os.Open(abs)
	if err != nil {
		return false, err
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 0, 64*1024), 1024*1024)
	for line := 1; sc.Scan(); line++ {
		text := sc.Text()
		if !re.MatchString(text) {
			continue
		}
		fmt.Fprintf(out, "%s:%d:%s\n", rel, line, core.RedactSecrets(strings.TrimSpace(text)))
		*results = *results + 1
		if *results >= maxResults || out.Len() >= maxBytes {
			return true, nil
		}
	}
	return false, sc.Err()
}

func safePath(root, requested string) (abs string, rel string, err error) {
	if requested == "" {
		return "", "", errors.New("path is required")
	}
	clean := filepath.Clean(filepath.FromSlash(requested))
	if filepath.IsAbs(clean) || strings.HasPrefix(clean, ".."+string(filepath.Separator)) || clean == ".." {
		return "", "", fmt.Errorf("path escapes project root: %s", requested)
	}
	rootAbs, err := filepath.Abs(root)
	if err != nil {
		return "", "", err
	}
	rootResolved, err := filepath.EvalSymlinks(rootAbs)
	if err != nil {
		return "", "", fmt.Errorf("resolve project root: %w", err)
	}
	abs = filepath.Join(rootAbs, clean)
	resolved, err := filepath.EvalSymlinks(abs)
	if err != nil {
		return "", "", fmt.Errorf("resolve requested path: %w", err)
	}
	relToRoot, err := filepath.Rel(rootResolved, resolved)
	if err != nil {
		return "", "", err
	}
	if relToRoot == ".." || strings.HasPrefix(relToRoot, ".."+string(filepath.Separator)) {
		return "", "", fmt.Errorf("path escapes project root: %s", requested)
	}
	return resolved, filepath.ToSlash(relToRoot), nil
}

func readBoundedFile(path string, maxBytes int) ([]byte, bool, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, false, err
	}
	defer f.Close()
	body, err := io.ReadAll(io.LimitReader(f, int64(maxBytes)+1))
	if err != nil {
		return nil, false, err
	}
	if len(body) > maxBytes {
		return body[:maxBytes], true, nil
	}
	return body, false, nil
}

func formatLineSlice(rel string, body []byte, start, end, maxBytes int, sourceTruncated bool) string {
	lines := strings.Split(string(body), "\n")
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	if start < 1 {
		start = 1
	}
	if end < 1 || end > len(lines) {
		end = len(lines)
	}
	if start > len(lines) || start > end {
		return fmt.Sprintf("%s: no lines in requested range\n", rel)
	}
	var out bytes.Buffer
	fmt.Fprintf(&out, "%s:%d-%d\n", rel, start, end)
	for i := start; i <= end; i++ {
		fmt.Fprintf(&out, "%6d  %s\n", i, core.RedactSecrets(lines[i-1]))
		if out.Len() >= maxBytes {
			out.WriteString("results truncated - refine your query\n")
			break
		}
	}
	if sourceTruncated {
		out.WriteString("source truncated at tool byte limit\n")
	}
	return out.String()
}

func formatBlame(rel string, line int, body []byte) string {
	fields := map[string]string{}
	sc := bufio.NewScanner(bytes.NewReader(body))
	var commit string
	if sc.Scan() {
		parts := strings.Fields(sc.Text())
		if len(parts) > 0 {
			commit = parts[0]
		}
	}
	for sc.Scan() {
		text := sc.Text()
		if text == "" || strings.HasPrefix(text, "\t") {
			continue
		}
		k, v, ok := strings.Cut(text, " ")
		if ok {
			fields[k] = v
		}
	}
	if commit == "" {
		return fmt.Sprintf("%s:%d: no blame data\n", rel, line)
	}
	return fmt.Sprintf("%s:%d commit=%s author=%s <%s> author-time=%s summary=%s\n",
		rel, line, commit, fields["author"], fields["author-mail"], fields["author-time"], fields["summary"])
}

func boundMax(n int) int {
	if n < 1 || n > MaxResultLines {
		return MaxResultLines
	}
	return n
}

func mustSchema(v any) json.RawMessage {
	b, err := json.Marshal(v)
	if err != nil {
		panic(err)
	}
	return b
}
