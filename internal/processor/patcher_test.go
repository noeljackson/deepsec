package processor

import (
	"bytes"
	"context"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"

	"github.com/noeljackson/deepsec/internal/core"
	"github.com/noeljackson/deepsec/internal/processor/providers"
	"github.com/stretchr/testify/require"
)

type sourcePatchMockBackend struct {
	body   string
	called int
}

func (m *sourcePatchMockBackend) Kind() providers.Kind { return providers.KindAnthropic }
func (m *sourcePatchMockBackend) Model() string        { return "mock-source-patch" }
func (m *sourcePatchMockBackend) ProposePatchJSON(context.Context, string, string, json.RawMessage) (string, core.Usage, float64, error) {
	m.called++
	return m.body, core.Usage{InputTokens: 10, OutputTokens: 5}, 0.01, nil
}
func (m *sourcePatchMockBackend) Investigate(context.Context, *InvestigateBatch) (*InvestigateOutput, error) {
	panic("unexpected Investigate")
}
func (m *sourcePatchMockBackend) Revalidate(context.Context, *RevalidateInput) ([]RevalidatedFinding, core.Usage, uint64, error) {
	panic("unexpected Revalidate")
}
func (m *sourcePatchMockBackend) Triage(context.Context, *TriageInput) (*TriagedFinding, core.Usage, uint64, error) {
	panic("unexpected Triage")
}

func TestRunPatchAppliesValidatesAndWritesProvenance(t *testing.T) {
	root := patchFixtureRepo(t)
	data := core.DataRootFromPath(filepath.Join(t.TempDir(), "data"))
	finding := patchFixtureFinding(root)
	backend := &sourcePatchMockBackend{body: patchJSON(t, sourcePatchDiff("bad", "good", "app.go"), []string{"app.go"})}
	var out bytes.Buffer

	res, err := RunPatch(context.Background(), patchTestOptions(root, data, backend, &out), finding)
	require.NoError(t, err)
	require.Equal(t, "patch", res.Decision)
	require.True(t, res.ValidationPassed)
	require.FileExists(t, res.PatchPath)
	require.Contains(t, out.String(), "validation=passed")

	body, err := os.ReadFile(res.PatchPath)
	require.NoError(t, err)
	require.Contains(t, string(body), `"finding_id": "`+finding.ID+`"`)
	require.Contains(t, string(body), `"validation_command": "grep -q good app.go"`)
}

func TestRunPatchMalformedDiffFailsGracefully(t *testing.T) {
	root := patchFixtureRepo(t)
	data := core.DataRootFromPath(filepath.Join(t.TempDir(), "data"))
	finding := patchFixtureFinding(root)
	backend := &sourcePatchMockBackend{body: patchJSON(t, "not a diff", []string{"app.go"})}

	_, err := RunPatch(context.Background(), patchTestOptions(root, data, backend, nil), finding)
	require.Error(t, err)
	path, _ := data.PatchJSONPath("p1", finding.ID)
	require.NoFileExists(t, path)
}

func TestRunPatchCannotFixLogsNoPatch(t *testing.T) {
	root := patchFixtureRepo(t)
	data := core.DataRootFromPath(filepath.Join(t.TempDir(), "data"))
	finding := patchFixtureFinding(root)
	logPath := filepath.Join(t.TempDir(), "PATCH_DECISIONS.md")
	backend := &sourcePatchMockBackend{body: `{"decision":"cannot-fix","confidence":"low","files_touched":[],"reason":"needs product decision"}`}
	opts := patchTestOptions(root, data, backend, nil)
	opts.DecisionLogPath = logPath

	res, err := RunPatch(context.Background(), opts, finding)
	require.NoError(t, err)
	require.Equal(t, "cannot-fix", res.Decision)
	path, _ := data.PatchJSONPath("p1", finding.ID)
	require.NoFileExists(t, path)
	log, err := os.ReadFile(logPath)
	require.NoError(t, err)
	require.Contains(t, string(log), "Decision: cannot-fix")
}

func TestRunPatchValidationFailureWritesNoProvenance(t *testing.T) {
	root := patchFixtureRepo(t)
	data := core.DataRootFromPath(filepath.Join(t.TempDir(), "data"))
	finding := patchFixtureFinding(root)
	backend := &sourcePatchMockBackend{body: patchJSON(t, sourcePatchDiff("bad", "good", "app.go"), []string{"app.go"})}
	opts := patchTestOptions(root, data, backend, nil)
	opts.ValidateCommand = "grep -q missing app.go"

	_, err := RunPatch(context.Background(), opts, finding)
	require.Error(t, err)
	path, _ := data.PatchJSONPath("p1", finding.ID)
	require.NoFileExists(t, path)
	body, err := os.ReadFile(filepath.Join(root, "app.go"))
	require.NoError(t, err)
	require.Contains(t, string(body), "bad")
}

func TestRunPatchApplyCommitsBranch(t *testing.T) {
	root := patchFixtureRepo(t)
	initGitRepo(t, root)
	data := core.DataRootFromPath(filepath.Join(t.TempDir(), "data"))
	finding := patchFixtureFinding(root)
	backend := &sourcePatchMockBackend{body: patchJSON(t, sourcePatchDiff("bad", "good", "app.go"), []string{"app.go"})}
	opts := patchTestOptions(root, data, backend, nil)
	opts.Apply = true

	res, err := RunPatch(context.Background(), opts, finding)
	require.NoError(t, err)
	require.NotEmpty(t, res.Commit)
	require.Equal(t, "deepsec-patch/"+finding.ID, res.Branch)
	branch := gitOut(t, root, "branch", "--show-current")
	require.Equal(t, res.Branch, branch)
	log := gitOut(t, root, "log", "-1", "--pretty=%B")
	require.Contains(t, log, "Finding-ID: "+finding.ID)
}

func TestRunPatchApplyDirtyTreeRefuses(t *testing.T) {
	root := patchFixtureRepo(t)
	initGitRepo(t, root)
	require.NoError(t, os.WriteFile(filepath.Join(root, "dirty.txt"), []byte("dirty\n"), 0o644))
	data := core.DataRootFromPath(filepath.Join(t.TempDir(), "data"))
	backend := &sourcePatchMockBackend{body: patchJSON(t, sourcePatchDiff("bad", "good", "app.go"), []string{"app.go"})}
	opts := patchTestOptions(root, data, backend, nil)
	opts.Apply = true

	_, err := RunPatch(context.Background(), opts, patchFixtureFinding(root))
	require.Error(t, err)
	require.Contains(t, err.Error(), "git tree is not clean")
	require.Zero(t, backend.called)
}

func TestRunPatchMultiFileDiffIsOutOfScope(t *testing.T) {
	root := patchFixtureRepo(t)
	require.NoError(t, os.WriteFile(filepath.Join(root, "other.go"), []byte("package main\nvar other = \"bad\"\n"), 0o644))
	data := core.DataRootFromPath(filepath.Join(t.TempDir(), "data"))
	finding := patchFixtureFinding(root)
	diff := sourcePatchDiff("bad", "good", "app.go") + "\n" + sourcePatchDiff("bad", "good", "other.go")
	backend := &sourcePatchMockBackend{body: patchJSON(t, diff, []string{"app.go", "other.go"})}

	res, err := RunPatch(context.Background(), patchTestOptions(root, data, backend, nil), finding)
	require.NoError(t, err)
	require.Equal(t, "out-of-scope", res.Decision)
	path, _ := data.PatchJSONPath("p1", finding.ID)
	require.NoFileExists(t, path)
}

func TestRunPatchRefusesDeepsecRepoRoot(t *testing.T) {
	cwd, err := os.Getwd()
	require.NoError(t, err)
	repo := gitOut(t, cwd, "rev-parse", "--show-toplevel")
	backend := &sourcePatchMockBackend{body: patchJSON(t, sourcePatchDiff("bad", "good", "app.go"), []string{"app.go"})}
	opts := patchTestOptions(repo, core.DataRootFromPath(filepath.Join(t.TempDir(), "data")), backend, nil)

	_, err = RunPatch(context.Background(), opts, patchFixtureFinding(repo))
	require.Error(t, err)
	require.Contains(t, err.Error(), "refusing to patch")
	require.Zero(t, backend.called)
}

func patchTestOptions(root string, data core.DataRoot, backend AgentBackend, out *bytes.Buffer) PatchRunOptions {
	var w interface{ Write([]byte) (int, error) } = out
	if out == nil {
		w = &bytes.Buffer{}
	}
	return PatchRunOptions{
		ProjectID: "p1", ProjectRoot: root, DataRoot: data, Backend: backend,
		ProviderName: "mock", ValidateCommand: "grep -q good app.go",
		DecisionLogPath: filepath.Join(filepath.Dir(data.Path), "PATCH_DECISIONS.md"),
		Out:             w, Now: func() time.Time { return time.Date(2026, 5, 13, 12, 0, 0, 0, time.UTC) },
	}
}

func patchFixtureRepo(t *testing.T) string {
	t.Helper()
	root := t.TempDir()
	body := "package main\n\nfunc message() string { return \"bad\" }\n"
	require.NoError(t, os.WriteFile(filepath.Join(root, "app.go"), []byte(body), 0o644))
	return root
}

func patchFixtureFinding(root string) PatchFinding {
	f := core.Finding{
		Severity: core.SeverityHigh, VulnSlug: "test-vuln", Title: "Bad string",
		Description: "bad is unsafe", LineNumbers: []int{3}, Confidence: core.ConfidenceHigh,
		ProducedByRunID: "run1",
	}
	return PatchFinding{
		ID: FindingID("p1", "app.go", 0, f), ProjectID: "p1", ProjectRoot: root,
		FilePath: "app.go", Index: 0, Finding: f,
	}
}

func patchJSON(t *testing.T, diff string, files []string) string {
	t.Helper()
	body, err := json.Marshal(SourcePatch{
		Decision: "patch", Diff: diff, Rationale: "replace bad with good",
		Confidence: "high", FilesTouched: files,
	})
	require.NoError(t, err)
	return string(body)
}

func sourcePatchDiff(old, new, path string) string {
	return "diff --git a/" + path + " b/" + path + "\n" +
		"--- a/" + path + "\n" +
		"+++ b/" + path + "\n" +
		"@@ -1,3 +1,3 @@\n" +
		" package main\n" +
		" \n" +
		"-func message() string { return \"" + old + "\" }\n" +
		"+func message() string { return \"" + new + "\" }\n"
}

func initGitRepo(t *testing.T, root string) {
	t.Helper()
	gitRun(t, root, "init", "--quiet")
	gitRun(t, root, "config", "user.email", "deepsec@example.com")
	gitRun(t, root, "config", "user.name", "deepsec")
	gitRun(t, root, "config", "commit.gpgsign", "false")
	gitRun(t, root, "add", ".")
	gitRun(t, root, "commit", "-m", "initial")
}

func gitRun(t *testing.T, root string, args ...string) {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", root}, args...)...)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "%s", out)
}

func gitOut(t *testing.T, root string, args ...string) string {
	t.Helper()
	cmd := exec.Command("git", append([]string{"-C", root}, args...)...)
	out, err := cmd.CombinedOutput()
	require.NoError(t, err, "%s", out)
	return string(bytes.TrimSpace(out))
}
