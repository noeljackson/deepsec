package bench

import (
	"bytes"
	"context"
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

	"github.com/BurntSushi/toml"
	"github.com/noeljackson/deepsec/internal/core"
	"github.com/noeljackson/deepsec/internal/processor"
	"github.com/noeljackson/deepsec/internal/scanner"
)

const agentDecisionsPath = "AGENT_DECISIONS.md"

type AgentOptions struct {
	Slug                    string
	TasksDir                string
	OutDir                  string
	Apply                   bool
	MaxIterations           int
	MaxRejections           int
	MaxCostUSD              float64
	CandidateGrowthBudget   float64
	HeldOut                 []string
	Backend                 processor.AgentBackend
	MockPatch               *processor.Patch
	RunTests                bool
	RequireClean            bool
	Out                     io.Writer
	Now                     func() time.Time
	ContextFalsePositiveCap int
	ContextFalseNegativeCap int
}

type GateReport struct {
	Accepted bool
	Reasons  []string
	Before   slugReview
	After    slugReview
}

func RunAgent(ctx context.Context, opts AgentOptions) error {
	opts = normalizeAgentOptions(opts)
	if err := validateSlugIfSet(opts.Slug); err != nil {
		return err
	}
	if len(opts.HeldOut) > 0 {
		for _, id := range opts.HeldOut {
			if err := core.AssertSafeSegment(id, "held-out task"); err != nil {
				return err
			}
		}
	}
	if opts.RequireClean {
		if err := requireCleanTree(); err != nil {
			return err
		}
	}
	taskIDs, heldOut, err := splitHeldOutTasks(opts.TasksDir, opts.HeldOut)
	if err != nil {
		return err
	}
	if len(taskIDs) == 0 {
		return errors.New("no non-held-out benchmark tasks to score")
	}
	var accepted, rejected int
	for accepted < opts.MaxIterations {
		baseline, err := Score(taskIDs, ScoreOptions{TasksDir: opts.TasksDir, OutDir: opts.OutDir})
		if err != nil {
			return err
		}
		var heldBaseline *RunResult
		if len(heldOut) > 0 {
			heldBaseline, err = Score(heldOut, ScoreOptions{TasksDir: opts.TasksDir, OutDir: opts.OutDir})
			if err != nil {
				return err
			}
		}
		slug := opts.Slug
		if slug == "" {
			slug, err = pickWorstPrecisionSlug(baseline)
			if err != nil {
				return err
			}
		}
		matcherPath, err := findMatcherSource(slug)
		if err != nil {
			return err
		}
		original, err := os.ReadFile(matcherPath)
		if err != nil {
			return err
		}
		currentMatcher, err := matcherBlock(original, slug)
		if err != nil {
			return err
		}
		baseReview := summarizeSlug(slug, baseline)
		patch, err := proposeAgentPatch(ctx, opts, slug, baseReview, currentMatcher)
		if err != nil {
			return err
		}
		if patch.NeedsEngineFeature {
			entry := decisionEntry(opts.Now(), slug, "needs-engine-feature", patch, GateReport{}, "", 0)
			if opts.Apply {
				if err := appendDecision(entry); err != nil {
					return err
				}
			}
			fmt.Fprintf(opts.Out, "Patch: %s\nGate: skipped (%s)\n", patch.Summary(), patch.Reason)
			return nil
		}
		fmt.Fprintf(opts.Out, "Patch: %s\n", patch.Summary())
		if opts.Apply {
			if err := applyPatchToMatcherFile(matcherPath, slug, patch); err != nil {
				_ = os.WriteFile(matcherPath, original, 0o644)
				return err
			}
			if err := verifyMatcherPatchScope(matcherPath, original, slug, patch); err != nil {
				_ = os.WriteFile(matcherPath, original, 0o644)
				return err
			}
		} else {
			preview, err := previewPatch(matcherPath, slug, patch)
			if err != nil {
				return err
			}
			fmt.Fprint(opts.Out, preview)
		}
		extraPaths, cleanup, err := candidateMatcherPaths(matcherPath, original, slug, patch, opts.Apply)
		if err != nil {
			return err
		}
		defer cleanup()
		candidate, err := Score(taskIDs, ScoreOptions{TasksDir: opts.TasksDir, OutDir: opts.OutDir, ExtraMatcherPaths: extraPaths})
		if err != nil {
			if opts.Apply {
				_ = os.WriteFile(matcherPath, original, 0o644)
			}
			return err
		}
		gate := EvaluateAgentGate(slug, baseline, candidate, opts.CandidateGrowthBudget)
		if gate.Accepted && opts.RunTests {
			if err := runAgentTests(); err != nil {
				gate.Accepted = false
				gate.Reasons = append(gate.Reasons, "go test failed: "+err.Error())
			}
		}
		fmt.Fprintf(opts.Out, "Gate: %s\n", gateStatus(gate))
		for _, reason := range gate.Reasons {
			fmt.Fprintf(opts.Out, "- %s\n", reason)
		}
		if len(heldOut) > 0 {
			if err := printHeldOutDelta(opts, heldOut, slug, heldBaseline, extraPaths); err != nil {
				return err
			}
		}
		if !opts.Apply {
			return nil
		}
		if !gate.Accepted {
			_ = os.WriteFile(matcherPath, original, 0o644)
			if err := appendDecision(decisionEntry(opts.Now(), slug, "rejected", patch, gate, "", 0)); err != nil {
				return err
			}
			rejected++
			if rejected >= opts.MaxRejections {
				return fmt.Errorf("halted after %d consecutive rejections", rejected)
			}
			if opts.Slug != "" {
				return nil
			}
			continue
		}
		regCases, err := appendAgentRegressionCases(opts, slug, baseReview, gate.After)
		if err != nil {
			_ = os.WriteFile(matcherPath, original, 0o644)
			return err
		}
		if err := appendDecision(decisionEntry(opts.Now(), slug, "accepted", patch, gate, "(pending)", regCases)); err != nil {
			return err
		}
		if err := runGit("add", matcherPath, regressionCasesPath, agentDecisionsPath); err != nil {
			return err
		}
		msg := fmt.Sprintf("agent(%s): %s", slug, rationaleSummary(patch))
		if err := runGit("commit", "-m", msg); err != nil {
			return err
		}
		hash, err := gitOutput("rev-parse", "--short", "HEAD")
		if err != nil {
			return err
		}
		commit := strings.TrimSpace(hash)
		fmt.Fprintf(opts.Out, "Committed %s\n", commit)
		accepted++
		rejected = 0
		if opts.Slug != "" {
			return nil
		}
	}
	return nil
}

func normalizeAgentOptions(opts AgentOptions) AgentOptions {
	if opts.Out == nil {
		opts.Out = os.Stdout
	}
	if opts.TasksDir == "" {
		opts.TasksDir = filepath.Join("bench", "tasks")
	}
	if opts.OutDir == "" {
		opts.OutDir = filepath.Join("bench", "out-agent")
	}
	if opts.MaxIterations <= 0 {
		opts.MaxIterations = 1
	}
	if opts.MaxRejections <= 0 {
		opts.MaxRejections = 3
	}
	if opts.CandidateGrowthBudget == 0 {
		opts.CandidateGrowthBudget = 0.05
	}
	if opts.Now == nil {
		opts.Now = time.Now
	}
	if opts.ContextFalsePositiveCap <= 0 {
		opts.ContextFalsePositiveCap = 8
	}
	if opts.ContextFalseNegativeCap <= 0 {
		opts.ContextFalseNegativeCap = 5
	}
	return opts
}

func validateSlugIfSet(slug string) error {
	if slug == "" {
		return nil
	}
	return validateSlug(slug)
}

func proposeAgentPatch(ctx context.Context, opts AgentOptions, slug string, review slugReview, currentMatcher string) (processor.Patch, error) {
	if opts.MockPatch != nil {
		p := *opts.MockPatch
		if err := p.Validate(); err != nil {
			return processor.Patch{}, err
		}
		return p, nil
	}
	if opts.Backend == nil {
		return processor.Patch{}, errors.New("agent requires a backend unless --mock-patch is supplied")
	}
	fps := make([]processor.PatchFalsePositive, 0, min(len(review.FalsePositives), opts.ContextFalsePositiveCap))
	for _, fp := range review.FalsePositives {
		if len(fps) >= opts.ContextFalsePositiveCap {
			break
		}
		fps = append(fps, processor.PatchFalsePositive{
			TaskID: fp.TaskID, File: fp.File, Line: fp.Line, Snippet: fp.Snippet, Matched: fp.Matched,
		})
	}
	fns := make([]processor.PatchFalseNegative, 0, min(len(review.FalseNegatives), opts.ContextFalseNegativeCap))
	for _, fn := range review.FalseNegatives {
		if len(fns) >= opts.ContextFalseNegativeCap {
			break
		}
		fns = append(fns, processor.PatchFalseNegative{
			TaskID: fn.TaskID, IssueID: fn.IssueID, File: fn.File, StartLine: fn.StartLine, EndLine: fn.EndLine,
			VulnSlugs: fn.VulnSlugs, ClosestCandidate: fn.ClosestCandidate, Reason: fn.Reason,
		})
	}
	return processor.ProposePatch(ctx, opts.Backend, slug, fps, fns, currentMatcher)
}

func pickWorstPrecisionSlug(result *RunResult) (string, error) {
	metrics := map[string]slugMetrics{}
	for _, row := range result.BySlug {
		m := metrics[row.Slug]
		m.Slug = row.Slug
		m.TruePositive += row.TruePositive
		m.FalsePositive += row.FalsePositive
		m.FalseNegative += row.FalseNegative
		m.CandidateCount += row.CandidateCount
		metrics[row.Slug] = m
	}
	var candidates []slugMetrics
	for _, m := range metrics {
		if m.FalsePositive <= 1 {
			continue
		}
		m.Precision = rate(m.TruePositive, m.CandidateCount)
		m.Recall = rate(m.TruePositive, m.TruePositive+m.FalseNegative)
		candidates = append(candidates, m)
	}
	if len(candidates) == 0 {
		return "", errors.New("no slug has more than 1 false positive")
	}
	sort.Slice(candidates, func(i, j int) bool {
		if candidates[i].Precision != candidates[j].Precision {
			return candidates[i].Precision < candidates[j].Precision
		}
		if candidates[i].FalsePositive != candidates[j].FalsePositive {
			return candidates[i].FalsePositive > candidates[j].FalsePositive
		}
		return candidates[i].Slug < candidates[j].Slug
	})
	return candidates[0].Slug, nil
}

func splitHeldOutTasks(tasksDir string, held []string) ([]string, []string, error) {
	all, err := discoverTasks(tasksDir)
	if err != nil {
		return nil, nil, err
	}
	heldSet := map[string]struct{}{}
	for _, id := range held {
		heldSet[id] = struct{}{}
	}
	var train, out []string
	for _, id := range all {
		if _, ok := heldSet[id]; ok {
			out = append(out, id)
		} else {
			train = append(train, id)
		}
	}
	return train, out, nil
}

func EvaluateAgentGate(slug string, before, after *RunResult, candidateBudget float64) GateReport {
	g := GateReport{Accepted: true, Before: summarizeSlug(slug, before), After: summarizeSlug(slug, after)}
	// Liveness: refuse patches that silence the matcher entirely on the
	// bench (it was producing candidates before, now fires zero times).
	// Precision becomes degenerate 1.0 when both TP and FP are zero, so
	// the precision/recall gates below pass vacuously; without this
	// guard, a `suppress_patterns = ["(?s).*"]` patch would be accepted
	// as an "improvement." See #18.
	if g.Before.Metrics.CandidateCount > 0 && g.After.Metrics.CandidateCount == 0 {
		g.Reasons = append(g.Reasons, fmt.Sprintf("matcher silenced: candidate count %d -> 0", g.Before.Metrics.CandidateCount))
	}
	// No-op detection: if the patch produced no observable change to
	// the bench *anywhere* (target slug unchanged AND total candidate
	// count unchanged AND every other slug's metrics unchanged), the
	// patch is decorative and should be rejected so the agent doesn't
	// claim an "improvement" it didn't actually make. See #18.
	if isBenchNoOp(before, after) {
		g.Reasons = append(g.Reasons, "no-op: patch produced no change in bench metrics")
	}
	if g.After.Metrics.Precision+1e-9 < g.Before.Metrics.Precision {
		g.Reasons = append(g.Reasons, fmt.Sprintf("target precision dropped %.2f -> %.2f", g.Before.Metrics.Precision, g.After.Metrics.Precision))
	}
	if g.After.Metrics.Recall+1e-9 < g.Before.Metrics.Recall {
		g.Reasons = append(g.Reasons, fmt.Sprintf("target recall dropped %.2f -> %.2f", g.Before.Metrics.Recall, g.After.Metrics.Recall))
	}
	beforePrecision := precisionBySlug(before)
	afterPrecision := precisionBySlug(after)
	for other, bp := range beforePrecision {
		if other == slug {
			continue
		}
		ap := afterPrecision[other]
		if bp-ap > 0.05+1e-9 {
			g.Reasons = append(g.Reasons, fmt.Sprintf("precision for %s dropped %.2f -> %.2f", other, bp, ap))
		}
	}
	beforeHC := highCriticalFNBySlug(before)
	afterHC := highCriticalFNBySlug(after)
	for other, base := range beforeHC {
		if other == slug {
			continue
		}
		if afterHC[other] > base {
			g.Reasons = append(g.Reasons, fmt.Sprintf("HIGH/CRITICAL recall for %s dropped (%d -> %d false negatives)", other, base, afterHC[other]))
		}
	}
	for other, afterCount := range afterHC {
		if other == slug {
			continue
		}
		if _, seen := beforeHC[other]; !seen && afterCount > 0 {
			g.Reasons = append(g.Reasons, fmt.Sprintf("HIGH/CRITICAL recall for %s dropped (0 -> %d false negatives)", other, afterCount))
		}
	}
	limit := int(float64(before.Summary.CandidateCountTotal)*(1+candidateBudget) + 0.999999)
	if after.Summary.CandidateCountTotal > limit {
		g.Reasons = append(g.Reasons, fmt.Sprintf("candidate count grew beyond budget (%d -> %d, limit %d)", before.Summary.CandidateCountTotal, after.Summary.CandidateCountTotal, limit))
	}
	g.Accepted = len(g.Reasons) == 0
	return g
}

// isBenchNoOp reports whether the bench observed no observable change
// between before and after. Used by the gate to reject decorative
// patches (#18). A no-op is conservatively defined: the total candidate
// count is identical, and every slug present in either run has the same
// TP / FP / FN / CandidateCount counts.
func isBenchNoOp(before, after *RunResult) bool {
	if before.Summary.CandidateCountTotal != after.Summary.CandidateCountTotal {
		return false
	}
	idx := func(r *RunResult) map[string]SlugResult {
		out := map[string]SlugResult{}
		for _, row := range r.BySlug {
			cur := out[row.Slug]
			cur.Slug = row.Slug
			cur.TruePositive += row.TruePositive
			cur.FalsePositive += row.FalsePositive
			cur.FalseNegative += row.FalseNegative
			cur.CandidateCount += row.CandidateCount
			out[row.Slug] = cur
		}
		return out
	}
	b, a := idx(before), idx(after)
	if len(b) != len(a) {
		return false
	}
	for slug, br := range b {
		ar, ok := a[slug]
		if !ok {
			return false
		}
		if br.TruePositive != ar.TruePositive || br.FalsePositive != ar.FalsePositive ||
			br.FalseNegative != ar.FalseNegative || br.CandidateCount != ar.CandidateCount {
			return false
		}
	}
	return true
}

func precisionBySlug(r *RunResult) map[string]float64 {
	counts := map[string]slugMetrics{}
	for _, row := range r.BySlug {
		m := counts[row.Slug]
		m.TruePositive += row.TruePositive
		m.CandidateCount += row.CandidateCount
		counts[row.Slug] = m
	}
	out := map[string]float64{}
	for slug, m := range counts {
		out[slug] = rate(m.TruePositive, m.CandidateCount)
	}
	return out
}

func highCriticalFNBySlug(r *RunResult) map[string]int {
	out := map[string]int{}
	for _, fn := range r.FalseNegatives {
		if fn.Severity != core.SeverityHigh && fn.Severity != core.SeverityCritical {
			continue
		}
		if len(fn.VulnSlugs) > 0 {
			out[fn.VulnSlugs[0]]++
		}
	}
	return out
}

func gateStatus(g GateReport) string {
	if g.Accepted {
		return "accepted"
	}
	return "rejected"
}

func applyPatchToMatcherFile(path, slug string, patch processor.Patch) error {
	if err := ensureMatcherPath(path); err != nil {
		return err
	}
	body, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	next, err := patchMatcherBytes(body, slug, patch)
	if err != nil {
		return err
	}
	if err := compileMatcherFile(path, next); err != nil {
		return err
	}
	return os.WriteFile(path, next, 0o644)
}

func previewPatch(path, slug string, patch processor.Patch) (string, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return "", err
	}
	next, err := patchMatcherBytes(body, slug, patch)
	if err != nil {
		return "", err
	}
	return simpleDiff(path, string(body), string(next)), nil
}

func candidateMatcherPaths(path string, original []byte, slug string, patch processor.Patch, applied bool) ([]string, func(), error) {
	if applied {
		return []string{path}, func() {}, nil
	}
	next, err := patchMatcherBytes(original, slug, patch)
	if err != nil {
		return nil, nil, err
	}
	tmp, err := os.MkdirTemp("", "deepsec-agent-matcher-")
	if err != nil {
		return nil, nil, err
	}
	tmpPath := filepath.Join(tmp, filepath.Base(path))
	if err := os.WriteFile(tmpPath, next, 0o644); err != nil {
		os.RemoveAll(tmp)
		return nil, nil, err
	}
	return []string{tmpPath}, func() { os.RemoveAll(tmp) }, nil
}

func patchMatcherBytes(body []byte, slug string, patch processor.Patch) ([]byte, error) {
	if err := patch.Validate(); err != nil {
		return nil, err
	}
	start, end, err := matcherBlockRange(body, slug)
	if err != nil {
		return nil, err
	}
	block := string(body[start:end])
	var next string
	switch patch.Decision {
	case "suppress_pattern":
		next = addArrayValue(block, "suppress_patterns", patch.SuppressPattern)
	case "require_content":
		next = addArrayValue(block, "require_content", patch.RequireContent)
	case "file_patterns":
		next = replaceArray(block, "file_patterns", patch.FilePatterns)
	case "requires_tech":
		next = addRequiresTech(block, patch.RequiresTech)
	default:
		return nil, fmt.Errorf("cannot apply decision %q", patch.Decision)
	}
	out := make([]byte, 0, len(body)-len(block)+len(next))
	out = append(out, body[:start]...)
	out = append(out, next...)
	out = append(out, body[end:]...)
	return out, nil
}

func matcherBlockRange(body []byte, slug string) (int, int, error) {
	re := regexp.MustCompile(`(?m)^\[\[matcher\]\]\s*$`)
	locs := re.FindAllIndex(body, -1)
	for i, loc := range locs {
		end := len(body)
		if i+1 < len(locs) {
			end = locs[i+1][0]
		}
		block := body[loc[0]:end]
		if bytes.Contains(block, []byte("slug = "+strconv.Quote(slug))) {
			return loc[0], end, nil
		}
	}
	return 0, 0, fmt.Errorf("matcher slug %q not found", slug)
}

func matcherBlock(body []byte, slug string) (string, error) {
	start, end, err := matcherBlockRange(body, slug)
	if err != nil {
		return "", err
	}
	return string(body[start:end]), nil
}

func addArrayValue(block, key, value string) string {
	if strings.Contains(block, strconv.Quote(value)) {
		return block
	}
	lines := strings.SplitAfter(block, "\n")
	for i, line := range lines {
		if !strings.HasPrefix(strings.TrimSpace(line), key+" = [") {
			continue
		}
		if strings.Contains(line, "]") {
			lines[i] = strings.Replace(line, "]", ", "+strconv.Quote(value)+"]", 1)
			return strings.Join(lines, "")
		}
		for j := i + 1; j < len(lines); j++ {
			if strings.TrimSpace(lines[j]) == "]" {
				lines = append(lines[:j], append([]string{"  " + strconv.Quote(value) + ",\n"}, lines[j:]...)...)
				return strings.Join(lines, "")
			}
		}
	}
	return insertBeforeBlockEnd(block, fmt.Sprintf("%s = [%s]\n", key, strconv.Quote(value)))
}

func replaceArray(block, key string, values []string) string {
	repl := fmt.Sprintf("%s = [%s]\n", key, quotedList(values))
	lines := strings.SplitAfter(block, "\n")
	for i, line := range lines {
		if !strings.HasPrefix(strings.TrimSpace(line), key+" = [") {
			continue
		}
		if strings.Contains(line, "]") {
			lines[i] = repl
			return strings.Join(lines, "")
		}
		j := i + 1
		for ; j < len(lines); j++ {
			if strings.TrimSpace(lines[j]) == "]" {
				break
			}
		}
		lines = append(append(lines[:i], repl), lines[j+1:]...)
		return strings.Join(lines, "")
	}
	return insertBeforeBlockEnd(block, repl)
}

func addRequiresTech(block string, tech []string) string {
	lineRe := regexp.MustCompile(`(?m)^requires = \{ tech = \[([^\]]*)\] \}\s*$`)
	if loc := lineRe.FindStringSubmatchIndex(block); loc != nil {
		existing := parseInlineStrings(block[loc[2]:loc[3]])
		for _, t := range tech {
			if !stringInSlice(t, existing) {
				existing = append(existing, t)
			}
		}
		return block[:loc[0]] + fmt.Sprintf("requires = { tech = [%s] }\n", quotedList(existing)) + block[loc[1]:]
	}
	return insertBeforeBlockEnd(block, fmt.Sprintf("requires = { tech = [%s] }\n", quotedList(tech)))
}

func insertBeforeBlockEnd(block, line string) string {
	if strings.HasSuffix(block, "\n") {
		return block + line
	}
	return block + "\n" + line
}

func quotedList(values []string) string {
	parts := make([]string, 0, len(values))
	for _, v := range values {
		parts = append(parts, strconv.Quote(v))
	}
	return strings.Join(parts, ", ")
}

func parseInlineStrings(s string) []string {
	var out []string
	for _, part := range strings.Split(s, ",") {
		part = strings.TrimSpace(part)
		if part == "" {
			continue
		}
		if unq, err := strconv.Unquote(part); err == nil {
			out = append(out, unq)
		}
	}
	return out
}

func verifyMatcherPatchScope(path string, before []byte, slug string, patch processor.Patch) error {
	if err := ensureMatcherPath(path); err != nil {
		return err
	}
	after, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var oldFile, newFile scanner.MatcherFile
	if err := toml.Unmarshal(before, &oldFile); err != nil {
		return err
	}
	if err := toml.Unmarshal(after, &newFile); err != nil {
		return err
	}
	if len(oldFile.Matchers) != len(newFile.Matchers) {
		return errors.New("patch changed matcher count")
	}
	for i := range oldFile.Matchers {
		oldM, newM := oldFile.Matchers[i], newFile.Matchers[i]
		if oldM.Slug != newM.Slug {
			return errors.New("patch changed matcher ordering or slug")
		}
		if oldM.Slug != slug {
			if fmt.Sprintf("%#v", oldM) != fmt.Sprintf("%#v", newM) {
				return fmt.Errorf("patch changed non-target matcher %q", oldM.Slug)
			}
			continue
		}
		oldM.SuppressPatterns = newM.SuppressPatterns
		oldM.RequireContent = newM.RequireContent
		oldM.FilePatterns = newM.FilePatterns
		oldM.Requires.Tech = newM.Requires.Tech
		if fmt.Sprintf("%#v", oldM) != fmt.Sprintf("%#v", newM) {
			return fmt.Errorf("patch changed fields outside allow-list for %q", slug)
		}
	}
	_ = patch
	return nil
}

func ensureMatcherPath(path string) error {
	rel, err := filepath.Rel(".", path)
	if err != nil {
		return err
	}
	rel = filepath.ToSlash(rel)
	if !strings.HasPrefix(rel, "internal/scanner/matchers/") || !strings.HasSuffix(rel, ".toml") {
		return fmt.Errorf("refusing to edit non-matcher path %s", path)
	}
	return core.AssertSafeFilePath(rel)
}

func compileMatcherFile(path string, body []byte) error {
	var f scanner.MatcherFile
	if err := toml.Unmarshal(body, &f); err != nil {
		return err
	}
	for _, m := range f.Matchers {
		if _, err := scanner.Compile(m); err != nil {
			return fmt.Errorf("%s: %w", path, err)
		}
	}
	return nil
}

func appendAgentRegressionCases(opts AgentOptions, slug string, before, after slugReview) (int, error) {
	afterFP, afterFN := fpKeys(after.FalsePositives), fnKeys(after.FalseNegatives)
	added := 0
	for _, fp := range before.FalsePositives {
		if _, ok := afterFP[fpKey(fp)]; ok {
			continue
		}
		content := strings.TrimSpace(fp.Snippet)
		if content == "" {
			content = readSourceContent(opts.TasksDir, fp.TaskID, fp.File, 0, 0)
		}
		if err := appendRegressionCase(regressionCasesPath, regressionCase{
			Slug:        slug,
			Expectation: "must_not_fire",
			Content:     content + "\n",
			FilePath:    fp.File,
			Reason:      "false positive removed by bounded-patch agent",
			SourceRef:   fp.Contradicts,
			AddedAt:     opts.Now().UTC().Format("2006-01-02"),
		}); err != nil {
			return added, err
		}
		added++
	}
	for _, fn := range before.FalseNegatives {
		if _, ok := afterFN[fnKey(fn)]; ok {
			continue
		}
		if err := appendRegressionCase(regressionCasesPath, regressionCase{
			Slug:        slug,
			Expectation: "must_fire",
			Content:     readSourceContent(opts.TasksDir, fn.TaskID, fn.File, fn.StartLine, fn.EndLine),
			FilePath:    fn.File,
			Reason:      "false negative resolved by bounded-patch agent",
			SourceRef:   fn.IssueID,
			AddedAt:     opts.Now().UTC().Format("2006-01-02"),
		}); err != nil {
			return added, err
		}
		added++
	}
	return added, nil
}

func decisionEntry(now time.Time, slug, status string, patch processor.Patch, gate GateReport, commit string, regCases int) string {
	var b strings.Builder
	fmt.Fprintf(&b, "## %s — slug=%s — %s\n", now.UTC().Format("2006-01-02T15:04Z"), slug, status)
	fmt.Fprintf(&b, "- Patch: %s\n", patch.Summary())
	if patch.Rationale != "" {
		fmt.Fprintf(&b, "- Rationale: %s\n", patch.Rationale)
	}
	if status == "accepted" {
		beforeFP, afterFP := len(gate.Before.FalsePositives), len(gate.After.FalsePositives)
		beforeFN, afterFN := len(gate.Before.FalseNegatives), len(gate.After.FalseNegatives)
		fmt.Fprintf(&b, "- FPs resolved: %d\n", max(0, beforeFP-afterFP))
		fmt.Fprintf(&b, "- FNs introduced: %d\n", max(0, afterFN-beforeFN))
		fmt.Fprintf(&b, "- Regression cases added: %d\n", regCases)
		fmt.Fprintf(&b, "- Provider: agent proposer\n")
		fmt.Fprintf(&b, "- Commit: %s\n", commit)
	} else {
		reason := patch.Reason
		if len(gate.Reasons) > 0 {
			reason = strings.Join(gate.Reasons, "; ")
		}
		if reason != "" {
			fmt.Fprintf(&b, "- Reason: %s\n", reason)
		}
		fmt.Fprintf(&b, "- No commit; file reverted.\n")
	}
	b.WriteByte('\n')
	return b.String()
}

func appendDecision(entry string) error {
	if err := core.AssertSafeFilePath(agentDecisionsPath); err != nil {
		return err
	}
	f, err := os.OpenFile(agentDecisionsPath, os.O_CREATE|os.O_WRONLY|os.O_APPEND, 0o644)
	if err != nil {
		return err
	}
	defer f.Close()
	_, err = f.WriteString(entry)
	return err
}

func printHeldOutDelta(opts AgentOptions, held []string, slug string, before *RunResult, extraPaths []string) error {
	after, err := Score(held, ScoreOptions{TasksDir: opts.TasksDir, OutDir: opts.OutDir, ExtraMatcherPaths: extraPaths})
	if err != nil {
		return err
	}
	b, a := summarizeSlug(slug, before), summarizeSlug(slug, after)
	fmt.Fprintf(opts.Out, "Held-out: precision %.2f -> %.2f, recall %.2f -> %.2f\n", b.Metrics.Precision, a.Metrics.Precision, b.Metrics.Recall, a.Metrics.Recall)
	return nil
}

func runAgentTests() error {
	cmd := exec.Command("go", "test", "./bench/...", "./cmd/benchsec/...", "./internal/processor/...", "./internal/scanner/...")
	cmd.Stdout = os.Stdout
	cmd.Stderr = os.Stderr
	return cmd.Run()
}

func requireCleanTree() error {
	out, err := exec.Command("git", "status", "--porcelain").Output()
	if err != nil {
		return err
	}
	if strings.TrimSpace(string(out)) != "" {
		return errors.New("git tree is not clean")
	}
	return nil
}

func simpleDiff(path, before, after string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "--- %s\n+++ %s (proposed)\n", path, path)
	if before == after {
		b.WriteString("(no changes)\n")
		return b.String()
	}
	oldLines := strings.Split(strings.TrimRight(before, "\n"), "\n")
	newLines := strings.Split(strings.TrimRight(after, "\n"), "\n")
	for _, line := range oldLines {
		if !containsLine(newLines, line) {
			fmt.Fprintf(&b, "-%s\n", line)
		}
	}
	for _, line := range newLines {
		if !containsLine(oldLines, line) {
			fmt.Fprintf(&b, "+%s\n", line)
		}
	}
	return b.String()
}

func containsLine(lines []string, target string) bool {
	for _, line := range lines {
		if line == target {
			return true
		}
	}
	return false
}

func rationaleSummary(p processor.Patch) string {
	if p.Rationale != "" {
		return firstWords(p.Rationale, 8)
	}
	return firstWords(p.Summary(), 8)
}

func firstWords(s string, n int) string {
	words := strings.Fields(s)
	if len(words) > n {
		words = words[:n]
	}
	if len(words) == 0 {
		return "bounded matcher patch"
	}
	return strings.Join(words, " ")
}

func stringInSlice(v string, xs []string) bool {
	for _, x := range xs {
		if x == v {
			return true
		}
	}
	return false
}
