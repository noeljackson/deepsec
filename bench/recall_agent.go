package bench

import (
	"context"
	"errors"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/noeljackson/deepsec/internal/core"
	"github.com/noeljackson/deepsec/internal/processor"
	"github.com/noeljackson/deepsec/internal/scanner"
)

// extraMatchersDir is where recall-mode proposals are written. It sits
// outside the bundled matcher pack so that promotion into the bundle
// is an explicit human review step.
const extraMatchersDir = "internal/scanner/matchers/extra"

// RecallAgentOptions configures the new-matcher proposer loop.
type RecallAgentOptions struct {
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
	MockProposal            *processor.NewMatcher
	RunTests                bool
	RequireClean            bool
	Out                     io.Writer
	Now                     func() time.Time
	ContextFalseNegativeCap int
	MinPrecision            float64
}

func RunRecallAgent(ctx context.Context, opts RecallAgentOptions) error {
	opts = normalizeRecallOptions(opts)
	if err := validateSlugIfSet(opts.Slug); err != nil {
		return err
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
		cluster, err := pickWorstRecallCluster(baseline, opts.Slug)
		if err != nil {
			return err
		}
		existing, err := allKnownSlugs()
		if err != nil {
			return err
		}
		proposal, err := proposeNewMatcher(ctx, opts, cluster, existing)
		if err != nil {
			return err
		}
		if proposal.NeedsEngineFeature {
			entry := recallDecisionEntry(opts.Now(), cluster.VulnSlug, "needs-engine-feature", proposal, GateReport{}, "")
			if opts.Apply {
				if err := appendDecision(entry); err != nil {
					return err
				}
			}
			fmt.Fprintf(opts.Out, "Proposal: %s\nGate: skipped (%s)\n", proposal.Summary(), proposal.Reason)
			return nil
		}
		if proposal.Decision == "cannot-fix" {
			entry := recallDecisionEntry(opts.Now(), cluster.VulnSlug, "cannot-fix", proposal, GateReport{}, "")
			if opts.Apply {
				if err := appendDecision(entry); err != nil {
					return err
				}
			}
			fmt.Fprintf(opts.Out, "Proposal: %s\n", proposal.Summary())
			return nil
		}
		fmt.Fprintf(opts.Out, "Proposal: %s\n", proposal.Summary())
		if existsSlug(existing, proposal.Slug) {
			return fmt.Errorf("proposer suggested slug %q which already exists", proposal.Slug)
		}
		extraDir, cleanup, err := writeProposalToExtra(proposal, opts.Apply)
		if err != nil {
			return err
		}
		defer cleanup()
		candidate, err := Score(taskIDs, ScoreOptions{TasksDir: opts.TasksDir, OutDir: opts.OutDir, ExtraMatcherPaths: []string{extraDir}})
		if err != nil {
			return err
		}
		gate := EvaluateRecallGate(cluster, proposal.Slug, baseline, candidate, opts.CandidateGrowthBudget, opts.MinPrecision)
		fmt.Fprintf(opts.Out, "Gate: %s\n", gateStatus(gate))
		for _, reason := range gate.Reasons {
			fmt.Fprintf(opts.Out, "- %s\n", reason)
		}
		if len(heldOut) > 0 {
			if err := printRecallHeldOutDelta(opts, heldOut, heldBaseline, extraDir); err != nil {
				return err
			}
		}
		if !opts.Apply {
			return nil
		}
		if !gate.Accepted {
			if err := appendDecision(recallDecisionEntry(opts.Now(), cluster.VulnSlug, "rejected", proposal, gate, "")); err != nil {
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
		// On apply, the file was already written by writeProposalToExtra
		// (cleanup is a no-op in apply mode). Commit it.
		if err := appendDecision(recallDecisionEntry(opts.Now(), cluster.VulnSlug, "accepted", proposal, gate, "(pending)")); err != nil {
			return err
		}
		extraFile := filepath.Join(extraMatchersDir, proposal.Slug+".toml")
		if err := runGit("add", extraFile, agentDecisionsPath); err != nil {
			return err
		}
		msg := fmt.Sprintf("recall(%s): %s", proposal.Slug, rationaleSummaryRecall(proposal))
		if err := runGit("commit", "-m", msg); err != nil {
			return err
		}
		accepted++
		rejected = 0
		if opts.Slug != "" {
			return nil
		}
	}
	return nil
}

func normalizeRecallOptions(opts RecallAgentOptions) RecallAgentOptions {
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
	if opts.ContextFalseNegativeCap <= 0 {
		opts.ContextFalseNegativeCap = 8
	}
	if opts.MinPrecision <= 0 {
		opts.MinPrecision = 0.25
	}
	return opts
}

func proposeNewMatcher(ctx context.Context, opts RecallAgentOptions, cluster recallCluster, existing []string) (processor.NewMatcher, error) {
	if opts.MockProposal != nil {
		p := *opts.MockProposal
		if err := p.Validate(); err != nil {
			return processor.NewMatcher{}, err
		}
		return p, nil
	}
	if opts.Backend == nil {
		return processor.NewMatcher{}, errors.New("recall agent requires a backend unless --mock-proposal is supplied")
	}
	fns := make([]processor.PatchFalseNegative, 0, len(cluster.FalseNegatives))
	for _, fn := range cluster.FalseNegatives {
		if len(fns) >= opts.ContextFalseNegativeCap {
			break
		}
		fns = append(fns, processor.PatchFalseNegative{
			TaskID: fn.TaskID, IssueID: fn.IssueID, File: fn.File, StartLine: fn.StartLine, EndLine: fn.EndLine,
			VulnSlugs: fn.VulnSlugs, ClosestCandidate: fn.ClosestCandidate, Reason: fn.Reason,
		})
	}
	return processor.ProposeNewMatcher(ctx, opts.Backend, processor.RecallCluster{
		VulnSlug:       cluster.VulnSlug,
		FalseNegatives: fns,
	}, existing)
}

// recallCluster is the bench-side cluster type containing the full
// FalseNegative records (including Severity), used by gate logic.
type recallCluster struct {
	VulnSlug       string
	FalseNegatives []FalseNegative
}

// VulnSlug returns the cluster's vuln slug — exposed for tests.
func (c recallCluster) Slug() string { return c.VulnSlug }

func pickWorstRecallCluster(result *RunResult, want string) (recallCluster, error) {
	if result == nil {
		return recallCluster{}, errors.New("nil baseline")
	}
	byVuln := map[string][]FalseNegative{}
	for _, fn := range result.FalseNegatives {
		if len(fn.VulnSlugs) == 0 {
			continue
		}
		v := fn.VulnSlugs[0]
		byVuln[v] = append(byVuln[v], fn)
	}
	if want != "" {
		fns, ok := byVuln[want]
		if !ok {
			return recallCluster{}, fmt.Errorf("no false negatives for vuln slug %q", want)
		}
		return recallCluster{VulnSlug: want, FalseNegatives: fns}, nil
	}
	if len(byVuln) == 0 {
		return recallCluster{}, errors.New("no false negatives in baseline")
	}
	type entry struct {
		slug    string
		total   int
		highCnt int
	}
	var entries []entry
	for slug, fns := range byVuln {
		e := entry{slug: slug, total: len(fns)}
		for _, fn := range fns {
			if fn.Severity == core.SeverityHigh || fn.Severity == core.SeverityCritical {
				e.highCnt++
			}
		}
		entries = append(entries, e)
	}
	sort.Slice(entries, func(i, j int) bool {
		if entries[i].highCnt != entries[j].highCnt {
			return entries[i].highCnt > entries[j].highCnt
		}
		if entries[i].total != entries[j].total {
			return entries[i].total > entries[j].total
		}
		return entries[i].slug < entries[j].slug
	})
	pick := entries[0].slug
	return recallCluster{VulnSlug: pick, FalseNegatives: byVuln[pick]}, nil
}

// EvaluateRecallGate decides whether a newly proposed matcher should
// land. The recall agent is symmetric to the precision agent's gate:
// instead of "did precision improve without breaking recall," it asks
// "did the targeted FNs shrink without making FPs explode or breaking
// other slugs."
func EvaluateRecallGate(cluster recallCluster, newSlug string, before, after *RunResult, candidateBudget, minPrecision float64) GateReport {
	g := GateReport{Accepted: true}
	if before == nil || after == nil {
		g.Accepted = false
		g.Reasons = append(g.Reasons, "missing baseline or candidate run")
		return g
	}
	beforeFNs := fnsForVuln(before, cluster.VulnSlug)
	afterFNs := fnsForVuln(after, cluster.VulnSlug)
	if afterFNs >= beforeFNs {
		g.Reasons = append(g.Reasons, fmt.Sprintf("new matcher did not reduce %s false negatives (%d -> %d)", cluster.VulnSlug, beforeFNs, afterFNs))
	}
	// Per-slug precision check on the *new* slug: ensure it isn't just
	// firing wildly. If the new matcher produced any candidates, require
	// minimum precision among them.
	if newSlugCands := candidatesForSlug(after, newSlug); newSlugCands > 0 {
		newSlugTP := truePositivesForSlug(after, newSlug)
		precision := rate(newSlugTP, newSlugCands)
		if precision+1e-9 < minPrecision {
			g.Reasons = append(g.Reasons, fmt.Sprintf("new matcher precision %.2f below threshold %.2f (%d TP / %d cand)", precision, minPrecision, newSlugTP, newSlugCands))
		}
	}
	// Existing slugs: no precision regression beyond 0.05, no
	// HIGH/CRITICAL recall regression for other slugs.
	beforePrec := precisionBySlug(before)
	afterPrec := precisionBySlug(after)
	for other, bp := range beforePrec {
		if other == newSlug {
			continue
		}
		ap := afterPrec[other]
		if bp-ap > 0.05+1e-9 {
			g.Reasons = append(g.Reasons, fmt.Sprintf("precision for %s dropped %.2f -> %.2f", other, bp, ap))
		}
	}
	beforeHC := highCriticalFNBySlug(before)
	afterHC := highCriticalFNBySlug(after)
	for other, base := range beforeHC {
		if other == newSlug {
			continue
		}
		if afterHC[other] > base {
			g.Reasons = append(g.Reasons, fmt.Sprintf("HIGH/CRITICAL recall for %s dropped (%d -> %d false negatives)", other, base, afterHC[other]))
		}
	}
	limit := int(float64(before.Summary.CandidateCountTotal)*(1+candidateBudget) + 0.999999)
	if after.Summary.CandidateCountTotal > limit {
		g.Reasons = append(g.Reasons, fmt.Sprintf("candidate count grew beyond budget (%d -> %d, limit %d)", before.Summary.CandidateCountTotal, after.Summary.CandidateCountTotal, limit))
	}
	g.Accepted = len(g.Reasons) == 0
	return g
}

func fnsForVuln(r *RunResult, vuln string) int {
	n := 0
	for _, fn := range r.FalseNegatives {
		if len(fn.VulnSlugs) > 0 && fn.VulnSlugs[0] == vuln {
			n++
		}
	}
	return n
}

func candidatesForSlug(r *RunResult, slug string) int {
	n := 0
	for _, row := range r.BySlug {
		if row.Slug == slug {
			n += row.CandidateCount
		}
	}
	return n
}

func truePositivesForSlug(r *RunResult, slug string) int {
	n := 0
	for _, row := range r.BySlug {
		if row.Slug == slug {
			n += row.TruePositive
		}
	}
	return n
}

func writeProposalToExtra(proposal processor.NewMatcher, apply bool) (string, func(), error) {
	if err := core.AssertSafeSegment(proposal.Slug, "slug"); err != nil {
		return "", func() {}, err
	}
	if err := validateProposalTOML(proposal.TOMLBody); err != nil {
		return "", func() {}, err
	}
	if apply {
		if err := os.MkdirAll(extraMatchersDir, 0o755); err != nil {
			return "", func() {}, err
		}
		path := filepath.Join(extraMatchersDir, proposal.Slug+".toml")
		if err := os.WriteFile(path, []byte(proposal.TOMLBody+"\n"), 0o644); err != nil {
			return "", func() {}, err
		}
		return extraMatchersDir, func() {}, nil
	}
	dir, err := os.MkdirTemp("", "deepsec-recall-*")
	if err != nil {
		return "", func() {}, err
	}
	path := filepath.Join(dir, proposal.Slug+".toml")
	if err := os.WriteFile(path, []byte(proposal.TOMLBody+"\n"), 0o644); err != nil {
		_ = os.RemoveAll(dir)
		return "", func() {}, err
	}
	cleanup := func() { _ = os.RemoveAll(dir) }
	return dir, cleanup, nil
}

func validateProposalTOML(body string) error {
	var f scanner.MatcherFile
	if err := toml.Unmarshal([]byte(body), &f); err != nil {
		return fmt.Errorf("proposed matcher TOML: %w", err)
	}
	if len(f.Matchers) != 1 {
		return fmt.Errorf("proposed matcher must contain exactly one [[matcher]] block, got %d", len(f.Matchers))
	}
	if _, err := scanner.Compile(f.Matchers[0]); err != nil {
		return fmt.Errorf("proposed matcher compile: %w", err)
	}
	return nil
}

func allKnownSlugs() ([]string, error) {
	reg, err := scanner.WithBuiltin()
	if err != nil {
		return nil, err
	}
	// Also include any extra matchers already in the extra/ pack so we
	// don't propose duplicates against in-flight proposals.
	if _, err := os.Stat(extraMatchersDir); err == nil {
		if err := reg.LoadTOMLDir(extraMatchersDir); err != nil {
			return nil, err
		}
	}
	return reg.Slugs(), nil
}

func existsSlug(existing []string, slug string) bool {
	for _, s := range existing {
		if s == slug {
			return true
		}
	}
	return false
}

func recallDecisionEntry(now time.Time, vulnSlug, status string, proposal processor.NewMatcher, gate GateReport, commit string) string {
	var b strings.Builder
	fmt.Fprintf(&b, "\n## %s recall vuln=%s status=%s\n\n", now.UTC().Format(time.RFC3339), vulnSlug, status)
	fmt.Fprintf(&b, "- Proposed slug: `%s`\n", proposal.Slug)
	fmt.Fprintf(&b, "- Decision: %s\n", proposal.Decision)
	if proposal.Rationale != "" {
		fmt.Fprintf(&b, "- Rationale: %s\n", proposal.Rationale)
	}
	if proposal.Reason != "" {
		fmt.Fprintf(&b, "- Reason: %s\n", proposal.Reason)
	}
	for _, r := range gate.Reasons {
		fmt.Fprintf(&b, "- Gate: %s\n", r)
	}
	if commit != "" {
		fmt.Fprintf(&b, "- Commit: %s\n", commit)
	}
	return b.String()
}

func rationaleSummaryRecall(p processor.NewMatcher) string {
	r := strings.TrimSpace(p.Rationale)
	if r == "" {
		return p.Decision
	}
	if idx := strings.IndexByte(r, '\n'); idx > 0 {
		r = r[:idx]
	}
	return r
}

func printRecallHeldOutDelta(opts RecallAgentOptions, heldOut []string, baseline *RunResult, extraDir string) error {
	if baseline == nil {
		return nil
	}
	candidate, err := Score(heldOut, ScoreOptions{TasksDir: opts.TasksDir, OutDir: opts.OutDir, ExtraMatcherPaths: []string{extraDir}})
	if err != nil {
		return err
	}
	beforeFNs := len(baseline.FalseNegatives)
	afterFNs := len(candidate.FalseNegatives)
	fmt.Fprintf(opts.Out, "Held-out FNs: %d -> %d (cand: %d -> %d)\n",
		beforeFNs, afterFNs, baseline.Summary.CandidateCountTotal, candidate.Summary.CandidateCountTotal)
	return nil
}
