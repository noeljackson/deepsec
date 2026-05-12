package commands_test

import (
	"bytes"
	"encoding/json"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"sync/atomic"
	"testing"

	"github.com/stretchr/testify/require"
)

// CLI end-to-end tests. We exec the freshly-built binary against a temp
// workspace and (for AI commands) a local mock HTTP server.

func buildBinary(t *testing.T) string {
	t.Helper()
	out := filepath.Join(t.TempDir(), "deepsec")
	if runtime.GOOS == "windows" {
		out += ".exe"
	}
	// Walk up to the repo root.
	_, thisFile, _, _ := runtime.Caller(0)
	// internal/cli/commands/cli_e2e_test.go → 3 levels up = repo root.
	repoRoot := filepath.Join(filepath.Dir(thisFile), "..", "..", "..")
	cmd := exec.Command("go", "build", "-o", out, "./cmd/deepsec")
	cmd.Dir = repoRoot
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		t.Fatalf("go build failed: %v\n%s", err, stderr.String())
	}
	return out
}

func fixturePath(t *testing.T) string {
	t.Helper()
	_, thisFile, _, _ := runtime.Caller(0)
	return filepath.Join(filepath.Dir(thisFile), "..", "..", "..", "fixtures/vulnerable-app")
}

func copyDir(t *testing.T, src, dst string) {
	t.Helper()
	require.NoError(t, os.MkdirAll(dst, 0o755))
	entries, err := os.ReadDir(src)
	require.NoError(t, err)
	for _, e := range entries {
		from := filepath.Join(src, e.Name())
		to := filepath.Join(dst, e.Name())
		if e.IsDir() {
			copyDir(t, from, to)
			continue
		}
		body, err := os.ReadFile(from)
		require.NoError(t, err)
		require.NoError(t, os.WriteFile(to, body, 0o644))
	}
}

type harness struct {
	binary    string
	cwd       string
	projectID string
}

func newHarness(t *testing.T) *harness {
	t.Helper()
	bin := buildBinary(t)
	tmp := t.TempDir()
	copyDir(t, fixturePath(t), filepath.Join(tmp, "app"))
	cfg := "default_agent = \"anthropic\"\n[[projects]]\nid = \"p1\"\nroot = \"./app\"\n"
	require.NoError(t, os.WriteFile(filepath.Join(tmp, "deepsec.config.toml"), []byte(cfg), 0o644))
	return &harness{binary: bin, cwd: tmp, projectID: "p1"}
}

func (h *harness) cmd(t *testing.T, args ...string) ([]byte, []byte, error) {
	t.Helper()
	cmd := exec.Command(h.binary, args...)
	cmd.Dir = h.cwd
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

func (h *harness) cmdEnv(t *testing.T, env []string, args ...string) ([]byte, []byte, error) {
	t.Helper()
	cmd := exec.Command(h.binary, args...)
	cmd.Dir = h.cwd
	cmd.Env = append(os.Environ(), env...)
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	return stdout.Bytes(), stderr.Bytes(), err
}

func TestCLIListMatchers(t *testing.T) {
	h := newHarness(t)
	out, _, err := h.cmd(t, "list-matchers")
	require.NoError(t, err)
	require.Contains(t, string(out), "matchers")
	require.Contains(t, string(out), "auth-bypass")
}

func TestCLIListProviders(t *testing.T) {
	h := newHarness(t)
	out, _, err := h.cmd(t, "list-providers")
	require.NoError(t, err)
	s := string(out)
	require.Contains(t, s, "anthropic")
	require.Contains(t, s, "openai")
	require.Contains(t, s, "glm")
	require.Contains(t, s, "kimi")
}

func TestCLIScanFindsPlantedVulnerabilities(t *testing.T) {
	h := newHarness(t)
	out, errOut, err := h.cmd(t, "scan", "--project-id", h.projectID)
	require.NoError(t, err, "%s", errOut)
	require.Contains(t, string(out), "candidates=")
}

func TestCLIScanFilesMode(t *testing.T) {
	h := newHarness(t)
	out, errOut, err := h.cmd(t, "scan", "--project-id", h.projectID,
		"--files", "src/api/users.ts,src/api/admin.ts")
	require.NoError(t, err, "%s", errOut)
	s := string(out)
	require.Contains(t, s, "mode=files")
	require.Contains(t, s, "files=2")
}

func TestCLIStatusAndReport(t *testing.T) {
	h := newHarness(t)
	_, _, err := h.cmd(t, "scan", "--project-id", h.projectID)
	require.NoError(t, err)
	out, _, err := h.cmd(t, "status", "--project-id", h.projectID)
	require.NoError(t, err)
	require.Contains(t, string(out), "pending:")
	_, _, err = h.cmd(t, "report", "--project-id", h.projectID)
	require.NoError(t, err)
	for _, name := range []string{"report.md", "report.json", "report.csv"} {
		_, err := os.Stat(filepath.Join(h.cwd, "data", h.projectID, "reports", name))
		require.NoError(t, err, "missing %s", name)
	}
}

func TestCLIPreflightFailsWithoutKey(t *testing.T) {
	h := newHarness(t)
	out, errOut, err := h.cmdEnv(t,
		[]string{"ANTHROPIC_API_KEY="},
		"preflight", "--agent", "anthropic",
	)
	require.Error(t, err, "preflight should have failed; stdout=%q stderr=%q", out, errOut)
	require.Contains(t, string(errOut), "ANTHROPIC_API_KEY")
}

func TestCLIPreflightSucceedsWithKey(t *testing.T) {
	h := newHarness(t)
	out, errOut, err := h.cmdEnv(t,
		[]string{"ANTHROPIC_API_KEY=fake"},
		"preflight", "--agent", "anthropic",
	)
	require.NoError(t, err, "%s", errOut)
	require.Contains(t, string(out), "preflight ok")
}

func TestCLIRejectsUnknownProject(t *testing.T) {
	h := newHarness(t)
	_, _, err := h.cmd(t, "scan", "--project-id", "nonexistent")
	require.Error(t, err)
}

// --- AI pipeline tests against a mock Anthropic HTTP server ---

// mockAnthropic returns an httptest.Server that replies to every POST
// with the canned response from `responder`. Records call count.
func mockAnthropic(t *testing.T, responder func(callIdx int, body []byte) (int, []byte)) (*httptest.Server, *atomic.Int32) {
	t.Helper()
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		idx := int(calls.Add(1)) - 1
		status, payload := responder(idx, body)
		w.Header().Set("Content-Type", "application/json")
		w.WriteHeader(status)
		_, _ = w.Write(payload)
	}))
	t.Cleanup(srv.Close)
	return srv, &calls
}

func anthropicFindingResponse(filePath string) []byte {
	body, _ := json.Marshal(map[string]any{
		"id":            "msg_test",
		"type":          "message",
		"role":          "assistant",
		"model":         "claude-sonnet-4-6",
		"stop_reason":   "tool_use",
		"stop_sequence": nil,
		"content": []map[string]any{
			{
				"type": "tool_use",
				"id":   "tool_call_1",
				"name": "report_findings",
				"input": map[string]any{
					"findings": []map[string]any{{
						"filePath":       filePath,
						"severity":       "HIGH",
						"vulnSlug":       "test-slug",
						"title":          "Mock SQLi",
						"description":    "Mocked",
						"lineNumbers":    []int{1},
						"recommendation": "Fix it",
						"confidence":     "high",
					}},
				},
			},
		},
		"usage": map[string]any{
			"input_tokens":                100,
			"output_tokens":               50,
			"cache_read_input_tokens":     0,
			"cache_creation_input_tokens": 0,
		},
	})
	return body
}

func TestCLIProcessWritesFindingsViaHTTPBackend(t *testing.T) {
	h := newHarness(t)
	_, _, err := h.cmd(t, "scan", "--project-id", h.projectID)
	require.NoError(t, err)

	srv, calls := mockAnthropic(t, func(_ int, _ []byte) (int, []byte) {
		return 200, anthropicFindingResponse("src/api/users.ts")
	})
	out, errOut, err := h.cmdEnv(t, []string{
		"ANTHROPIC_API_KEY=fake",
		"ANTHROPIC_BASE_URL=" + srv.URL,
	},
		"process", "--project-id", h.projectID,
		"--batch-size", "2", "--concurrency", "2",
	)
	require.NoError(t, err, "%s", errOut)
	require.Contains(t, string(out), "findings=")

	recPath := filepath.Join(h.cwd, "data", h.projectID, "files/src/api/users.ts.json")
	body, err := os.ReadFile(recPath)
	require.NoError(t, err)
	require.Contains(t, string(body), `"Mock SQLi"`)
	require.GreaterOrEqual(t, calls.Load(), int32(1))
}

func TestCLIProcessQuotaExhaustion(t *testing.T) {
	h := newHarness(t)
	_, _, err := h.cmd(t, "scan", "--project-id", h.projectID)
	require.NoError(t, err)

	srv, _ := mockAnthropic(t, func(_ int, _ []byte) (int, []byte) {
		body, _ := json.Marshal(map[string]any{
			"type":  "error",
			"error": map[string]any{"type": "rate_limit_error", "message": "rate limit"},
		})
		return 429, body
	})
	out, errOut, _ := h.cmdEnv(t, []string{
		"ANTHROPIC_API_KEY=fake",
		"ANTHROPIC_BASE_URL=" + srv.URL,
	},
		"process", "--project-id", h.projectID,
	)
	// We don't require non-zero status — the run completes with the
	// quota flag set — but the stdout must indicate quota exhaustion.
	combined := string(out) + string(errOut)
	require.True(t,
		strings.Contains(combined, "quota") || strings.Contains(combined, "rate"),
		"expected quota signal in output; got: %s", combined)
}

func TestCLIPrCommentRenders(t *testing.T) {
	h := newHarness(t)
	_, _, err := h.cmd(t, "scan", "--project-id", h.projectID)
	require.NoError(t, err)

	srv, _ := mockAnthropic(t, func(_ int, _ []byte) (int, []byte) {
		return 200, anthropicFindingResponse("src/api/users.ts")
	})
	_, _, err = h.cmdEnv(t, []string{
		"ANTHROPIC_API_KEY=fake",
		"ANTHROPIC_BASE_URL=" + srv.URL,
	},
		"process", "--project-id", h.projectID, "--batch-size", "5")
	require.NoError(t, err)

	out, _, err := h.cmd(t, "pr-comment", "--project-id", h.projectID)
	require.NoError(t, err)
	s := string(out)
	require.Contains(t, s, "Mock SQLi")
	require.Contains(t, s, "HIGH")
	require.Contains(t, s, "src/api/users.ts")
}

func TestCLIPrCommentSkipEmptyExitsWhenNoRun(t *testing.T) {
	h := newHarness(t)
	_, _, err := h.cmd(t, "scan", "--project-id", h.projectID)
	require.NoError(t, err)
	_, _, err = h.cmd(t, "pr-comment", "--project-id", h.projectID, "--skip-empty")
	require.Error(t, err) // no recent process run
}
