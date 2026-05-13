package bench

import (
	"bufio"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/noeljackson/deepsec/internal/core"
	"github.com/noeljackson/deepsec/internal/scanner"
)

const regressionCasesPath = "internal/scanner/regression_cases.toml"

type editor interface {
	Run(path string) error
}

type envEditor struct{}

func (envEditor) Run(path string) error {
	name := os.Getenv("EDITOR")
	if name == "" {
		name = "vi"
	}
	cmd := exec.Command(name, path)
	cmd.Stdin = os.Stdin
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

type ReviewOptions struct {
	Slug          string
	TasksDir      string
	OutDir        string
	Edit          bool
	CommitMessage string
	EmitFPs       bool
	EmitFNs       bool
	Rescore       bool
	In            io.Reader
	Out           io.Writer
	Editor        editor
	Now           func() time.Time
}

type slugMetrics struct {
	Slug           string  `json:"slug"`
	Precision      float64 `json:"precision"`
	Recall         float64 `json:"recall"`
	TruePositive   int     `json:"true_positive"`
	FalsePositive  int     `json:"false_positive"`
	FalseNegative  int     `json:"false_negative"`
	CandidateCount int     `json:"candidate_count"`
}

type slugReview struct {
	Metrics        slugMetrics     `json:"metrics"`
	FalsePositives []FalsePositive `json:"false_positives"`
	FalseNegatives []FalseNegative `json:"false_negatives"`
}

type reviewState struct {
	Slug        string     `json:"slug"`
	MatcherPath string     `json:"matcher_path"`
	Baseline    slugReview `json:"baseline"`
	Accepted    slugReview `json:"accepted"`
	AcceptedAt  string     `json:"accepted_at"`
}

func RunReview(opts ReviewOptions) error {
	if opts.Out == nil {
		opts.Out = os.Stdout
	}
	if opts.In == nil {
		opts.In = os.Stdin
	}
	if opts.Editor == nil {
		opts.Editor = envEditor{}
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if err := validateSlug(opts.Slug); err != nil {
		return err
	}
	modes := 0
	for _, on := range []bool{opts.Edit, opts.CommitMessage != "", opts.EmitFPs, opts.EmitFNs, opts.Rescore} {
		if on {
			modes++
		}
	}
	if modes > 1 {
		return errors.New("choose only one of --edit, --commit, --emit-fps, --emit-fns, or --rescore")
	}
	switch {
	case opts.Edit:
		return runReviewEdit(opts)
	case opts.CommitMessage != "":
		return runReviewCommit(opts)
	case opts.EmitFPs:
		report, err := scoreSlug(opts, nil)
		if err != nil {
			return err
		}
		fps := report.FalsePositives
		if fps == nil {
			fps = []FalsePositive{}
		}
		return writeJSONTo(opts.Out, fps)
	case opts.EmitFNs:
		report, err := scoreSlug(opts, nil)
		if err != nil {
			return err
		}
		fns := report.FalseNegatives
		if fns == nil {
			fns = []FalseNegative{}
		}
		return writeJSONTo(opts.Out, fns)
	case opts.Rescore:
		report, err := scoreSlug(opts, nil)
		if err != nil {
			return err
		}
		fmt.Fprint(opts.Out, formatReviewReport(report))
		return nil
	default:
		report, err := scoreSlug(opts, nil)
		if err != nil {
			return err
		}
		fmt.Fprint(opts.Out, formatReviewReport(report))
		return nil
	}
}

func runReviewEdit(opts ReviewOptions) error {
	matcherPath, err := findMatcherSource(opts.Slug)
	if err != nil {
		return err
	}
	original, err := os.ReadFile(matcherPath)
	if err != nil {
		return err
	}
	baseline, err := scoreSlug(opts, []string{matcherPath})
	if err != nil {
		return err
	}
	reader := bufio.NewReader(opts.In)
	for {
		if err := opts.Editor.Run(matcherPath); err != nil {
			_ = os.WriteFile(matcherPath, original, 0o644)
			return err
		}
		current, err := scoreSlug(opts, []string{matcherPath})
		if err != nil {
			_ = os.WriteFile(matcherPath, original, 0o644)
			return err
		}
		fmt.Fprint(opts.Out, formatMetricDelta(baseline, current))
		if reviewsEqual(baseline, current) {
			fmt.Fprintln(opts.Out, "No metric delta; nothing to accept.")
			return nil
		}
		fmt.Fprint(opts.Out, "accept (a), discard (d), edit again (e)? ")
		answer, _ := reader.ReadString('\n')
		switch strings.ToLower(strings.TrimSpace(answer)) {
		case "a", "accept":
			state := reviewState{
				Slug:        opts.Slug,
				MatcherPath: matcherPath,
				Baseline:    baseline,
				Accepted:    current,
				AcceptedAt:  opts.Now().UTC().Format(time.RFC3339),
			}
			if err := writeReviewState(opts, state); err != nil {
				return err
			}
			return nil
		case "d", "discard":
			return os.WriteFile(matcherPath, original, 0o644)
		case "e", "edit", "":
			continue
		default:
			fmt.Fprintln(opts.Out, "Please choose accept (a), discard (d), or edit again (e).")
		}
	}
}

func runReviewCommit(opts ReviewOptions) error {
	state, err := readReviewState(opts)
	if err != nil {
		return err
	}
	current, err := scoreSlug(opts, []string{state.MatcherPath})
	if err != nil {
		return err
	}
	if !metricsImproved(state.Baseline.Metrics, current.Metrics) {
		return fmt.Errorf("slug %q metrics do not improve vs last accepted baseline", opts.Slug)
	}
	regCase, err := regressionFromDelta(opts, state.Baseline, current)
	if err != nil {
		return err
	}
	if err := appendRegressionCase(regressionCasesPath, regCase); err != nil {
		return err
	}
	if err := runGit("add", state.MatcherPath, regressionCasesPath); err != nil {
		return err
	}
	if err := runGit("commit", "-m", opts.CommitMessage); err != nil {
		return err
	}
	hash, err := gitOutput("rev-parse", "--short", "HEAD")
	if err != nil {
		return err
	}
	fmt.Fprintf(opts.Out, "Committed %s\n", strings.TrimSpace(hash))
	return nil
}

func scoreSlug(opts ReviewOptions, extraMatcherPaths []string) (slugReview, error) {
	result, err := Score(nil, ScoreOptions{
		TasksDir:          opts.TasksDir,
		OutDir:            opts.OutDir,
		ExtraMatcherPaths: extraMatcherPaths,
	})
	if err != nil {
		return slugReview{}, err
	}
	return summarizeSlug(opts.Slug, result), nil
}

func summarizeSlug(slug string, result *RunResult) slugReview {
	out := slugReview{Metrics: slugMetrics{Slug: slug}}
	for _, row := range result.BySlug {
		if row.Slug != slug {
			continue
		}
		out.Metrics.TruePositive += row.TruePositive
		out.Metrics.FalsePositive += row.FalsePositive
		out.Metrics.FalseNegative += row.FalseNegative
		out.Metrics.CandidateCount += row.CandidateCount
	}
	out.Metrics.Precision = rate(out.Metrics.TruePositive, out.Metrics.CandidateCount)
	out.Metrics.Recall = rate(out.Metrics.TruePositive, out.Metrics.TruePositive+out.Metrics.FalseNegative)
	for _, fp := range result.FalsePositives {
		if fp.Slug == slug {
			out.FalsePositives = append(out.FalsePositives, fp)
		}
	}
	for _, fn := range result.FalseNegatives {
		if SlugMatches(slug, fn.VulnSlugs) {
			out.FalseNegatives = append(out.FalseNegatives, fn)
		}
	}
	sort.Slice(out.FalsePositives, func(i, j int) bool { return fpKey(out.FalsePositives[i]) < fpKey(out.FalsePositives[j]) })
	sort.Slice(out.FalseNegatives, func(i, j int) bool { return fnKey(out.FalseNegatives[i]) < fnKey(out.FalseNegatives[j]) })
	return out
}

func formatReviewReport(r slugReview) string {
	var b strings.Builder
	m := r.Metrics
	fmt.Fprintf(&b, "=== %s (precision %.2f, recall %.2f) ===\n\n", m.Slug, m.Precision, m.Recall)
	fmt.Fprintf(&b, "False positives (%d):\n", len(r.FalsePositives))
	if len(r.FalsePositives) == 0 {
		b.WriteString("  none\n")
	}
	for _, fp := range r.FalsePositives {
		fmt.Fprintf(&b, "  bench/tasks/%s/source/%s:%d\n", fp.TaskID, fp.File, fp.Line)
		line := firstNonEmptyLine(fp.Snippet)
		if line != "" || fp.Matched != "" {
			fmt.Fprintf(&b, "    %s", line)
			if fp.Matched != "" {
				fmt.Fprintf(&b, " // matched: %q", fp.Matched)
			}
			b.WriteByte('\n')
		}
		if fp.Contradicts != "" && fp.Contradicts != "no entry" {
			fmt.Fprintf(&b, "    contradicts decoy: %s\n", fp.Contradicts)
		}
	}
	fmt.Fprintf(&b, "\nFalse negatives (%d):\n", len(r.FalseNegatives))
	if len(r.FalseNegatives) == 0 {
		b.WriteString("  none\n")
	}
	for _, fn := range r.FalseNegatives {
		fmt.Fprintf(&b, "  answer %s in %s:%d-%d (must_emit_candidate=true)\n", fn.IssueID, fn.File, fn.StartLine, fn.EndLine)
		fmt.Fprintf(&b, "    %s\n", fn.Reason)
		if fn.ClosestCandidate != "" {
			fmt.Fprintf(&b, "    closest: %s\n", fn.ClosestCandidate)
		}
	}
	return b.String()
}

func formatMetricDelta(before, after slugReview) string {
	var b strings.Builder
	fmt.Fprintf(&b, "Old: precision %.2f, recall %.2f, FP count %d, FN count %d\n",
		before.Metrics.Precision, before.Metrics.Recall, len(before.FalsePositives), len(before.FalseNegatives))
	fmt.Fprintf(&b, "New: precision %.2f, recall %.2f, FP count %d, FN count %d\n",
		after.Metrics.Precision, after.Metrics.Recall, len(after.FalsePositives), len(after.FalseNegatives))
	writeSetDelta(&b, "False positives disappeared", "New false positives", fpKeys(before.FalsePositives), fpKeys(after.FalsePositives))
	writeSetDelta(&b, "False negatives resolved", "New false negatives", fnKeys(before.FalseNegatives), fnKeys(after.FalseNegatives))
	return b.String()
}

func writeSetDelta(b *strings.Builder, removedLabel, addedLabel string, before, after map[string]struct{}) {
	removed, added := setMinus(before, after), setMinus(after, before)
	fmt.Fprintf(b, "%s (%d):\n", removedLabel, len(removed))
	for _, item := range removed {
		fmt.Fprintf(b, "  %s\n", item)
	}
	if len(removed) == 0 {
		b.WriteString("  none\n")
	}
	fmt.Fprintf(b, "%s (%d):\n", addedLabel, len(added))
	for _, item := range added {
		fmt.Fprintf(b, "  %s\n", item)
	}
	if len(added) == 0 {
		b.WriteString("  none\n")
	}
}

func metricsImproved(old, cur slugMetrics) bool {
	if cur.FalsePositive > old.FalsePositive || cur.FalseNegative > old.FalseNegative {
		return false
	}
	return cur.FalsePositive < old.FalsePositive || cur.FalseNegative < old.FalseNegative ||
		cur.Precision > old.Precision || cur.Recall > old.Recall
}

func reviewsEqual(a, b slugReview) bool {
	return a.Metrics == b.Metrics && equalKeys(fpKeys(a.FalsePositives), fpKeys(b.FalsePositives)) && equalKeys(fnKeys(a.FalseNegatives), fnKeys(b.FalseNegatives))
}

func findMatcherSource(slug string) (string, error) {
	matcherDir, err := repoPath(filepath.Join("internal", "scanner", "matchers"))
	if err != nil {
		return "", err
	}
	paths, err := filepath.Glob(filepath.Join(matcherDir, "*.toml"))
	if err != nil {
		return "", err
	}
	for _, path := range paths {
		var f scanner.MatcherFile
		if _, err := toml.DecodeFile(path, &f); err != nil {
			return "", err
		}
		for _, m := range f.Matchers {
			if m.Slug == slug {
				return path, nil
			}
		}
	}
	return "", fmt.Errorf("matcher source for slug %q not found under internal/scanner/matchers", slug)
}

func repoPath(rel string) (string, error) {
	for _, prefix := range []string{".", ".."} {
		path := filepath.Join(prefix, rel)
		if _, err := os.Stat(path); err == nil {
			return path, nil
		}
	}
	return "", fmt.Errorf("repository path %s not found", rel)
}

func regressionFromDelta(opts ReviewOptions, before, after slugReview) (regressionCase, error) {
	afterFP, afterFN := fpKeys(after.FalsePositives), fnKeys(after.FalseNegatives)
	for _, fp := range before.FalsePositives {
		if _, ok := afterFP[fpKey(fp)]; ok {
			continue
		}
		content := strings.TrimSpace(fp.Snippet)
		if content == "" {
			content = readSourceContent(opts.TasksDir, fp.TaskID, fp.File, 0, 0)
		}
		return regressionCase{
			Slug:        opts.Slug,
			Expectation: "must_not_fire",
			Content:     content + "\n",
			FilePath:    fp.File,
			Reason:      "false positive removed by matcher review",
			SourceRef:   fp.Contradicts,
			AddedAt:     opts.Now().UTC().Format("2006-01-02"),
		}, nil
	}
	for _, fn := range before.FalseNegatives {
		if _, ok := afterFN[fnKey(fn)]; ok {
			continue
		}
		return regressionCase{
			Slug:        opts.Slug,
			Expectation: "must_fire",
			Content:     readSourceContent(opts.TasksDir, fn.TaskID, fn.File, fn.StartLine, fn.EndLine),
			FilePath:    fn.File,
			Reason:      "false negative resolved by matcher review",
			SourceRef:   fn.IssueID,
			AddedAt:     opts.Now().UTC().Format("2006-01-02"),
		}, nil
	}
	return regressionCase{}, errors.New("accepted edit has no resolved false positive or false negative to capture")
}

type regressionCase struct {
	Slug        string
	Expectation string
	Content     string
	FilePath    string
	Reason      string
	SourceRef   string
	AddedAt     string
}

func appendRegressionCase(path string, c regressionCase) error {
	if err := core.AssertSafeFilePath(path); err != nil {
		return err
	}
	var b strings.Builder
	if body, err := os.ReadFile(path); err == nil {
		b.Write(body)
		if !strings.HasSuffix(b.String(), "\n") {
			b.WriteByte('\n')
		}
	} else if !os.IsNotExist(err) {
		return err
	}
	b.WriteString("\n[[case]]\n")
	fmt.Fprintf(&b, "slug = %s\n", strconv.Quote(c.Slug))
	fmt.Fprintf(&b, "expectation = %s\n", strconv.Quote(c.Expectation))
	fmt.Fprintf(&b, "content = %s\n", strconv.Quote(c.Content))
	fmt.Fprintf(&b, "file_path = %s\n", strconv.Quote(c.FilePath))
	fmt.Fprintf(&b, "reason = %s\n", strconv.Quote(c.Reason))
	if c.SourceRef != "" && c.SourceRef != "no entry" {
		fmt.Fprintf(&b, "source_ref = %s\n", strconv.Quote(c.SourceRef))
	}
	fmt.Fprintf(&b, "added_at = %s\n", strconv.Quote(c.AddedAt))
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func readSourceContent(tasksDir, taskID, file string, start, end int) string {
	if tasksDir == "" {
		tasksDir = filepath.Join("bench", "tasks")
	}
	body, err := os.ReadFile(filepath.Join(tasksDir, taskID, "source", filepath.FromSlash(file)))
	if err != nil {
		return ""
	}
	content := strings.ReplaceAll(string(body), "\r\n", "\n")
	if start <= 0 || end <= 0 {
		return content
	}
	lines := strings.Split(content, "\n")
	if start < 1 {
		start = 1
	}
	if end > len(lines) {
		end = len(lines)
	}
	if start > end {
		return content
	}
	return strings.Join(lines[start-1:end], "\n") + "\n"
}

func statePath(opts ReviewOptions) (string, error) {
	if opts.OutDir == "" {
		opts.OutDir = filepath.Join("bench", "out")
	}
	if err := validateSlug(opts.Slug); err != nil {
		return "", err
	}
	return filepath.Join(opts.OutDir, "review-state", opts.Slug+".json"), nil
}

func writeReviewState(opts ReviewOptions, state reviewState) error {
	path, err := statePath(opts)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	body, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, append(body, '\n'), 0o644)
}

func readReviewState(opts ReviewOptions) (reviewState, error) {
	path, err := statePath(opts)
	if err != nil {
		return reviewState{}, err
	}
	body, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return reviewState{}, fmt.Errorf("--commit requires a prior accepted --edit for slug %q", opts.Slug)
		}
		return reviewState{}, err
	}
	var state reviewState
	if err := json.Unmarshal(body, &state); err != nil {
		return reviewState{}, err
	}
	if state.Slug != opts.Slug {
		return reviewState{}, fmt.Errorf("review state slug mismatch: got %q, want %q", state.Slug, opts.Slug)
	}
	return state, nil
}

func validateSlug(slug string) error {
	if err := core.AssertSafeSegment(slug, "slug"); err != nil {
		return err
	}
	return nil
}

func firstNonEmptyLine(snippet string) string {
	for _, line := range strings.Split(snippet, "\n") {
		line = strings.TrimSpace(line)
		if line != "" {
			return line
		}
	}
	return ""
}

func fpKey(fp FalsePositive) string {
	return fmt.Sprintf("%s:%s:%d:%s:%s", fp.TaskID, fp.File, fp.Line, fp.Slug, fp.Matched)
}

func fnKey(fn FalseNegative) string {
	return fmt.Sprintf("%s:%s:%s:%d-%d", fn.TaskID, fn.IssueID, fn.File, fn.StartLine, fn.EndLine)
}

func fpKeys(xs []FalsePositive) map[string]struct{} {
	out := map[string]struct{}{}
	for _, x := range xs {
		out[fpKey(x)] = struct{}{}
	}
	return out
}

func fnKeys(xs []FalseNegative) map[string]struct{} {
	out := map[string]struct{}{}
	for _, x := range xs {
		out[fnKey(x)] = struct{}{}
	}
	return out
}

func setMinus(a, b map[string]struct{}) []string {
	var out []string
	for k := range a {
		if _, ok := b[k]; !ok {
			out = append(out, k)
		}
	}
	sort.Strings(out)
	return out
}

func equalKeys(a, b map[string]struct{}) bool {
	if len(a) != len(b) {
		return false
	}
	for k := range a {
		if _, ok := b[k]; !ok {
			return false
		}
	}
	return true
}

func writeJSONTo(w io.Writer, v any) error {
	body, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	_, err = fmt.Fprintln(w, string(body))
	return err
}

func runGit(args ...string) error {
	cmd := exec.Command("git", args...)
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func gitOutput(args ...string) (string, error) {
	body, err := exec.Command("git", args...).Output()
	return string(body), err
}
