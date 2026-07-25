package processor

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/noeljackson/deepsec/internal/core"
)

const PatchDecisionsPath = "PATCH_DECISIONS.md"

type PatchRunOptions struct {
	ProjectID         string
	ProjectRoot       string
	GithubURL         string
	DataRoot          core.DataRoot
	Backend           AgentBackend
	ProviderName      string
	ModelSettings     ModelSettings
	ValidateCommand   string
	ValidationTimeout time.Duration
	Apply             bool
	Push              bool
	WithTools         bool
	MaxCostUSD        float64
	DecisionLogPath   string
	Out               io.Writer
	Now               func() time.Time
}

type PatchRunResult struct {
	FindingID         string
	Decision          string
	PatchPath         string
	ValidationPassed  bool
	ValidationSkipped bool
	Branch            string
	Commit            string
	CostUSD           float64
}

type PatchProvenance struct {
	FindingID          string         `json:"finding_id"`
	ProjectID          string         `json:"project_id"`
	FilePath           string         `json:"file_path"`
	Decision           string         `json:"decision"`
	Diff               string         `json:"diff,omitempty"`
	Rationale          string         `json:"rationale,omitempty"`
	Confidence         string         `json:"confidence,omitempty"`
	FilesTouched       []string       `json:"files_touched,omitempty"`
	Reason             string         `json:"reason,omitempty"`
	Provider           string         `json:"provider"`
	Model              string         `json:"model"`
	ModelConfig        map[string]any `json:"model_config,omitempty"`
	Usage              core.Usage     `json:"usage"`
	CostUSD            float64        `json:"cost_usd"`
	ValidationCommand  string         `json:"validation_command,omitempty"`
	ValidationExitCode int            `json:"validation_exit_code"`
	ValidationStdout   string         `json:"validation_stdout_tail,omitempty"`
	ValidationStderr   string         `json:"validation_stderr_tail,omitempty"`
	ValidationSkipped  bool           `json:"validation_skipped"`
	Applied            bool           `json:"applied"`
	Branch             string         `json:"branch,omitempty"`
	Commit             string         `json:"commit,omitempty"`
	CreatedAt          string         `json:"created_at"`
}

type validationResult struct {
	Command  string
	ExitCode int
	Stdout   string
	Stderr   string
	Skipped  bool
}

func RunPatch(ctx context.Context, opts PatchRunOptions, finding PatchFinding) (PatchRunResult, error) {
	opts = normalizePatchRunOptions(opts)
	if err := validatePatchRunOptions(opts); err != nil {
		return PatchRunResult{}, err
	}
	if err := refuseSelfPatch(opts.ProjectRoot); err != nil {
		return PatchRunResult{}, err
	}
	if opts.Apply || opts.Push {
		if err := requireCleanGitTree(opts.ProjectRoot); err != nil {
			return PatchRunResult{}, err
		}
	}

	proposal, err := ProposeSourcePatch(ctx, opts.Backend, finding, opts.WithTools, opts.MaxCostUSD)
	if err != nil {
		return PatchRunResult{}, err
	}
	if opts.MaxCostUSD > 0 && proposal.Cost > opts.MaxCostUSD {
		return PatchRunResult{}, fmt.Errorf("patch cost $%.4f exceeds cap $%.4f", proposal.Cost, opts.MaxCostUSD)
	}
	patch := proposal.Patch
	if patch.Decision == "patch" && patchTouchesOutsideFinding(patch.FilesTouched, finding.FilePath) {
		patch.Decision = "out-of-scope"
		patch.Reason = "diff touches files outside reported file"
	}
	result := PatchRunResult{FindingID: finding.ID, Decision: patch.Decision, CostUSD: proposal.Cost}
	if patch.Decision != "patch" {
		if err := appendPatchDecision(opts, finding, patch, validationResult{}, "", ""); err != nil {
			return result, err
		}
		fmt.Fprintf(opts.Out, "patch finding=%s decision=%s reason=%s\n", finding.ID, patch.Decision, patch.Reason)
		return result, nil
	}

	clone, cleanup, err := materializePatchSource(opts.ProjectRoot, opts.GithubURL)
	if err != nil {
		return result, err
	}
	defer cleanup()
	validation, err := applyAndValidatePatch(ctx, clone, patch.Diff, opts.ValidateCommand, opts.ValidationTimeout)
	if err != nil {
		_ = appendPatchDecision(opts, finding, patch, validation, "", "")
		return result, err
	}
	result.ValidationPassed = validation.ExitCode == 0 && !validation.Skipped
	result.ValidationSkipped = validation.Skipped

	var branch, commit string
	if opts.Apply {
		branch, commit, err = commitPatch(opts.ProjectRoot, finding, patch, opts.Push)
		if err != nil {
			_ = appendPatchDecision(opts, finding, patch, validation, branch, commit)
			return result, err
		}
		result.Branch = branch
		result.Commit = commit
	}
	path, err := writePatchProvenance(opts, finding, patch, proposal, validation, branch, commit)
	if err != nil {
		return result, err
	}
	result.PatchPath = path
	if err := appendPatchDecision(opts, finding, patch, validation, branch, commit); err != nil {
		return result, err
	}
	if validation.Skipped {
		fmt.Fprintf(opts.Out, "patch finding=%s decision=patch validation=skipped patch=%s\n", finding.ID, path)
	} else {
		fmt.Fprintf(opts.Out, "patch finding=%s decision=patch validation=passed patch=%s\n", finding.ID, path)
	}
	if commit != "" {
		fmt.Fprintf(opts.Out, "committed branch=%s commit=%s\n", branch, commit)
	}
	return result, nil
}

func normalizePatchRunOptions(opts PatchRunOptions) PatchRunOptions {
	if opts.Out == nil {
		opts.Out = os.Stdout
	}
	if opts.ValidationTimeout == 0 {
		opts.ValidationTimeout = 5 * time.Minute
	}
	if opts.DecisionLogPath == "" {
		opts.DecisionLogPath = PatchDecisionsPath
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	return opts
}

func validatePatchRunOptions(opts PatchRunOptions) error {
	if opts.ProjectID == "" {
		return errors.New("project id is required")
	}
	if opts.ProjectRoot == "" {
		return errors.New("project root is required")
	}
	if opts.Push && !opts.Apply {
		return errors.New("--push requires --apply")
	}
	return nil
}

func patchTouchesOutsideFinding(files []string, findingFile string) bool {
	if len(files) != 1 {
		return true
	}
	return files[0] != filepath.ToSlash(filepath.Clean(filepath.FromSlash(findingFile)))
}

func materializePatchSource(projectRoot, githubURL string) (string, func(), error) {
	dir, err := os.MkdirTemp("", "deepsec-patch-")
	if err != nil {
		return "", nil, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	if githubURL != "" {
		commit, err := gitOutputIn(projectRoot, "rev-parse", "HEAD")
		if err == nil && strings.TrimSpace(commit) != "" {
			if err := runGitInDir(dir, "init", "--quiet"); err != nil {
				cleanup()
				return "", nil, err
			}
			if err := runGitInDir(dir, "remote", "add", "origin", githubURL); err != nil {
				cleanup()
				return "", nil, err
			}
			sha := strings.TrimSpace(commit)
			if err := runGitInDir(dir, "fetch", "--quiet", "--depth", "1", "origin", sha); err != nil {
				cleanup()
				return "", nil, fmt.Errorf("fetch %s @ %s: %w", githubURL, sha, err)
			}
			if err := runGitInDir(dir, "checkout", "--quiet", sha); err != nil {
				cleanup()
				return "", nil, err
			}
			return dir, cleanup, nil
		}
	}
	if err := copyTree(projectRoot, dir); err != nil {
		cleanup()
		return "", nil, err
	}
	if err := runGitInDir(dir, "init", "--quiet"); err != nil {
		cleanup()
		return "", nil, err
	}
	return dir, cleanup, nil
}

func applyAndValidatePatch(ctx context.Context, root, diff, validate string, timeout time.Duration) (validationResult, error) {
	diffPath := filepath.Join(root, ".deepsec.patch")
	if err := os.WriteFile(diffPath, []byte(diff+"\n"), 0o600); err != nil {
		return validationResult{}, err
	}
	defer os.Remove(diffPath)
	if err := runGitInDir(root, "apply", "--check", diffPath); err != nil {
		return validationResult{}, fmt.Errorf("git apply --check: %w", err)
	}
	if err := runGitInDir(root, "apply", diffPath); err != nil {
		return validationResult{}, fmt.Errorf("git apply: %w", err)
	}
	if strings.TrimSpace(validate) == "" {
		return validationResult{Skipped: true, ExitCode: 0}, nil
	}
	vctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(vctx, shellName(), shellFlag(), validate)
	cmd.Dir = root
	var stdout, stderr bytes.Buffer
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	err := cmd.Run()
	res := validationResult{
		Command:  validate,
		Stdout:   tailString(stdout.String(), 8192),
		Stderr:   tailString(stderr.String(), 8192),
		ExitCode: exitCode(err),
	}
	if vctx.Err() == context.DeadlineExceeded {
		res.ExitCode = -1
		return res, fmt.Errorf("validation timed out after %s", timeout)
	}
	if err != nil {
		return res, fmt.Errorf("validation failed: %w", err)
	}
	return res, nil
}

func commitPatch(root string, finding PatchFinding, patch SourcePatch, push bool) (string, string, error) {
	branch := "deepsec-patch/" + finding.ID
	if err := runGitInDir(root, "checkout", "-b", branch); err != nil {
		return branch, "", err
	}
	diffPath := filepath.Join(root, ".deepsec.patch")
	if err := os.WriteFile(diffPath, []byte(patch.Diff+"\n"), 0o600); err != nil {
		return branch, "", err
	}
	defer os.Remove(diffPath)
	if err := runGitInDir(root, "apply", diffPath); err != nil {
		return branch, "", err
	}
	args := append([]string{"add", "--"}, patch.FilesTouched...)
	if err := runGitInDir(root, args...); err != nil {
		return branch, "", err
	}
	msg := fmt.Sprintf("deepsec patch: %s\n\nFinding-ID: %s\nProject-ID: %s\nFile: %s\nSlug: %s\nConfidence: %s\n\n%s",
		finding.Finding.Title, finding.ID, finding.ProjectID, finding.FilePath, finding.Finding.VulnSlug, patch.Confidence, patch.Rationale)
	if err := runGitInDir(root, "commit", "-m", msg); err != nil {
		return branch, "", err
	}
	hash, err := gitOutputIn(root, "rev-parse", "--short", "HEAD")
	if err != nil {
		return branch, "", err
	}
	commit := strings.TrimSpace(hash)
	if push {
		if err := runGitInDir(root, "push", "-u", "origin", branch); err != nil {
			return branch, commit, err
		}
		if err := runCommandIn(root, "gh", "pr", "create", "--fill"); err != nil {
			return branch, commit, err
		}
	}
	return branch, commit, nil
}

func writePatchProvenance(opts PatchRunOptions, finding PatchFinding, patch SourcePatch, proposal SourcePatchProposal, validation validationResult, branch, commit string) (string, error) {
	path, err := opts.DataRoot.PatchJSONPath(opts.ProjectID, finding.ID)
	if err != nil {
		return "", err
	}
	if err := securePatchOutputDir(filepath.Dir(path)); err != nil {
		return "", err
	}
	prov := PatchProvenance{
		FindingID: finding.ID, ProjectID: opts.ProjectID, FilePath: finding.FilePath,
		Decision: patch.Decision, Diff: core.RedactSecrets(patch.Diff), Rationale: core.RedactSecrets(patch.Rationale),
		Confidence: patch.Confidence, FilesTouched: patch.FilesTouched, Reason: core.RedactSecrets(patch.Reason),
		Provider: opts.ProviderName, ModelConfig: opts.ModelSettings.AsMap(),
		Usage: proposal.Usage, CostUSD: proposal.Cost,
		ValidationCommand: core.RedactSecrets(validation.Command), ValidationExitCode: validation.ExitCode,
		ValidationStdout: core.RedactSecrets(validation.Stdout), ValidationStderr: core.RedactSecrets(validation.Stderr),
		ValidationSkipped: validation.Skipped, Applied: commit != "", Branch: branch, Commit: commit,
		CreatedAt: opts.Now().UTC().Format(time.RFC3339),
	}
	if opts.Backend != nil {
		prov.Model = opts.Backend.Model()
	}
	body, err := json.MarshalIndent(prov, "", "  ")
	if err != nil {
		return "", err
	}
	return path, writePrivatePatchFile(path, body)
}

func appendPatchDecision(opts PatchRunOptions, finding PatchFinding, patch SourcePatch, validation validationResult, branch, commit string) error {
	var b strings.Builder
	fmt.Fprintf(&b, "## %s finding=%s\n\n", opts.Now().UTC().Format(time.RFC3339), finding.ID)
	fmt.Fprintf(&b, "- Project: %s\n- File: %s\n- Slug: %s\n- Decision: %s\n", opts.ProjectID, finding.FilePath, finding.Finding.VulnSlug, patch.Decision)
	if patch.Rationale != "" {
		fmt.Fprintf(&b, "- Rationale: %s\n", core.RedactSecrets(patch.Rationale))
	}
	if patch.Reason != "" {
		fmt.Fprintf(&b, "- Reason: %s\n", core.RedactSecrets(patch.Reason))
	}
	if validation.Skipped {
		fmt.Fprintf(&b, "- Validation: skipped\n")
	} else if validation.Command != "" {
		fmt.Fprintf(&b, "- Validation: exit=%d command=%q\n", validation.ExitCode, core.RedactSecrets(validation.Command))
	}
	if branch != "" {
		fmt.Fprintf(&b, "- Branch: %s\n", branch)
	}
	if commit != "" {
		fmt.Fprintf(&b, "- Commit: %s\n", commit)
	}
	b.WriteString("\n")
	f, err := os.OpenFile(opts.DecisionLogPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o600)
	if err != nil {
		return err
	}
	defer f.Close()
	if err := os.Chmod(opts.DecisionLogPath, 0o600); err != nil {
		return err
	}
	_, err = f.WriteString(b.String())
	return err
}

func securePatchOutputDir(path string) error {
	if err := os.MkdirAll(path, 0o700); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing symlinked patch output directory: %s", path)
	}
	return os.Chmod(path, 0o700)
}

func writePrivatePatchFile(path string, body []byte) error {
	if info, err := os.Lstat(path); err == nil && info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("refusing to overwrite symlinked patch provenance: %s", path)
	} else if err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	f, err := os.OpenFile(path, os.O_WRONLY|os.O_CREATE|os.O_TRUNC, 0o600)
	if err != nil {
		return err
	}
	if _, err := f.Write(body); err != nil {
		_ = f.Close()
		return err
	}
	if err := f.Close(); err != nil {
		return err
	}
	return os.Chmod(path, 0o600)
}

func refuseSelfPatch(projectRoot string) error {
	target, err := filepath.Abs(projectRoot)
	if err != nil {
		return err
	}
	target, _ = filepath.EvalSymlinks(target)
	here, err := os.Getwd()
	if err != nil {
		return err
	}
	repo, err := gitOutputIn(here, "rev-parse", "--show-toplevel")
	if err != nil {
		return nil
	}
	root := strings.TrimSpace(repo)
	root, _ = filepath.EvalSymlinks(root)
	if root != "" && target == root {
		return errors.New("refusing to patch the deepsec repository itself")
	}
	return nil
}

func requireCleanGitTree(root string) error {
	out, err := gitOutputIn(root, "status", "--porcelain")
	if err != nil {
		return err
	}
	if strings.TrimSpace(out) != "" {
		return errors.New("git tree is not clean")
	}
	return nil
}

func copyTree(src, dst string) error {
	return filepath.WalkDir(src, func(path string, d os.DirEntry, err error) error {
		if err != nil {
			return err
		}
		rel, err := filepath.Rel(src, path)
		if err != nil {
			return err
		}
		if rel == "." {
			return nil
		}
		if d.IsDir() {
			if d.Name() == ".git" {
				return filepath.SkipDir
			}
			return os.MkdirAll(filepath.Join(dst, rel), 0o755)
		}
		info, err := d.Info()
		if err != nil {
			return err
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return err
		}
		return os.WriteFile(filepath.Join(dst, rel), body, info.Mode().Perm())
	})
}

func runGitInDir(dir string, args ...string) error {
	return runCommandIn(dir, "git", append([]string{"-C", dir}, args...)...)
}

func runCommandIn(dir, name string, args ...string) error {
	cmd := exec.Command(name, args...)
	cmd.Dir = dir
	stderr := &strings.Builder{}
	cmd.Stdout = io.Discard
	cmd.Stderr = stderr
	if err := cmd.Run(); err != nil {
		return fmt.Errorf("%s %v: %w (%s)", name, args, err, strings.TrimSpace(stderr.String()))
	}
	return nil
}

func gitOutputIn(dir string, args ...string) (string, error) {
	cmd := exec.Command("git", append([]string{"-C", dir}, args...)...)
	var stderr bytes.Buffer
	cmd.Stderr = &stderr
	out, err := cmd.Output()
	if err != nil {
		return "", fmt.Errorf("git %v: %w (%s)", args, err, strings.TrimSpace(stderr.String()))
	}
	return string(out), nil
}

func shellName() string { return "sh" }
func shellFlag() string { return "-c" }

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	var ee *exec.ExitError
	if errors.As(err, &ee) {
		return ee.ExitCode()
	}
	return -1
}

func tailString(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[len(s)-max:]
}
