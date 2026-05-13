package bench

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/noeljackson/deepsec/internal/core"
	"github.com/noeljackson/deepsec/internal/processor"
	"github.com/stretchr/testify/require"
)

func TestAgentGateAcceptsCandidateReduction(t *testing.T) {
	before := &RunResult{
		Summary: Summary{CandidateCountTotal: 2},
		BySlug:  []SlugResult{{Slug: "a", TruePositive: 1, FalsePositive: 1, CandidateCount: 2}},
	}
	after := &RunResult{
		Summary: Summary{CandidateCountTotal: 1},
		BySlug:  []SlugResult{{Slug: "a", TruePositive: 1, CandidateCount: 1}},
	}
	gate := EvaluateAgentGate("a", before, after, 0.05)
	require.True(t, gate.Accepted)
	require.Empty(t, gate.Reasons)
}

func TestAgentGateRejectsMatcherSilencingPatch(t *testing.T) {
	// Catches a `(?s).*` style suppress that silences the matcher
	// entirely. Pre-#18 the gate accepted this because precision and
	// recall both collapsed to a degenerate 1.0 with TP=FP=0.
	before := &RunResult{
		Summary: Summary{CandidateCountTotal: 6},
		BySlug:  []SlugResult{{Slug: "a", TruePositive: 0, FalsePositive: 6, CandidateCount: 6}},
	}
	after := &RunResult{
		Summary: Summary{CandidateCountTotal: 0},
		BySlug:  []SlugResult{{Slug: "a", TruePositive: 0, FalsePositive: 0, CandidateCount: 0}},
	}
	gate := EvaluateAgentGate("a", before, after, 0.05)
	require.False(t, gate.Accepted)
	require.Contains(t, gate.Reasons[0], "matcher silenced")
}

func TestAgentGateRejectsNoOpPatch(t *testing.T) {
	// Catches a decorative patch (e.g. `suppress_patterns =
	// ["(?i)admin_required"]` when nothing in the fixtures matches
	// that regex). Slug metrics are byte-identical pre and post.
	before := &RunResult{
		Summary: Summary{CandidateCountTotal: 3},
		BySlug:  []SlugResult{{Slug: "a", TruePositive: 1, FalsePositive: 2, CandidateCount: 3}},
	}
	after := &RunResult{
		Summary: Summary{CandidateCountTotal: 3},
		BySlug:  []SlugResult{{Slug: "a", TruePositive: 1, FalsePositive: 2, CandidateCount: 3}},
	}
	gate := EvaluateAgentGate("a", before, after, 0.05)
	require.False(t, gate.Accepted)
	require.Contains(t, gate.Reasons[0], "no-op")
}

func TestAgentGateAcceptsRealNarrowing(t *testing.T) {
	// Sanity: a patch that drops one FP without dropping the TP still
	// passes — the new gates shouldn't make legitimate improvements
	// look like silencing or no-ops.
	before := &RunResult{
		Summary: Summary{CandidateCountTotal: 3},
		BySlug:  []SlugResult{{Slug: "a", TruePositive: 1, FalsePositive: 2, CandidateCount: 3}},
	}
	after := &RunResult{
		Summary: Summary{CandidateCountTotal: 2},
		BySlug:  []SlugResult{{Slug: "a", TruePositive: 1, FalsePositive: 1, CandidateCount: 2}},
	}
	gate := EvaluateAgentGate("a", before, after, 0.05)
	require.True(t, gate.Accepted, "real narrowing must still pass: %v", gate.Reasons)
}

func TestAgentGateRejectsOtherSlugHighRecallRegression(t *testing.T) {
	before := &RunResult{
		Summary: Summary{CandidateCountTotal: 2},
		BySlug: []SlugResult{
			{Slug: "a", TruePositive: 1, CandidateCount: 1},
			{Slug: "b", TruePositive: 1, CandidateCount: 1},
		},
	}
	after := &RunResult{
		Summary: Summary{CandidateCountTotal: 2},
		BySlug: []SlugResult{
			{Slug: "a", TruePositive: 1, CandidateCount: 1},
			{Slug: "b", TruePositive: 1, CandidateCount: 1, FalseNegative: 1},
		},
		FalseNegatives: []FalseNegative{{Severity: core.SeverityHigh, VulnSlugs: []string{"b"}}},
	}
	gate := EvaluateAgentGate("a", before, after, 0.05)
	require.False(t, gate.Accepted)
	require.Contains(t, gate.Reasons[0], "HIGH/CRITICAL recall for b dropped")
}

func TestAgentDryRunLeavesMatcherUnchanged(t *testing.T) {
	path := filepath.Join("..", "internal", "scanner", "matchers", "python.toml")
	before, err := os.ReadFile(path)
	require.NoError(t, err)

	var out bytes.Buffer
	err = RunAgent(context.Background(), AgentOptions{
		Slug:       "flask-route",
		TasksDir:   "tasks",
		OutDir:     filepath.Join(t.TempDir(), "out"),
		MockPatch:  &processor.Patch{Decision: "suppress_pattern", SuppressPattern: "(?i)admin_required", Rationale: "test patch"},
		Out:        &out,
		RunTests:   false,
		Now:        func() time.Time { return time.Date(2026, 5, 13, 12, 0, 0, 0, time.UTC) },
		MaxCostUSD: 1,
	})
	require.NoError(t, err)
	after, err := os.ReadFile(path)
	require.NoError(t, err)
	require.Equal(t, string(before), string(after))
	require.Contains(t, out.String(), "Patch: added suppress_pattern")
	require.Contains(t, out.String(), "Gate:")
}

func TestAgentHeldOutPrintsSeparateDelta(t *testing.T) {
	var out bytes.Buffer
	err := RunAgent(context.Background(), AgentOptions{
		Slug:     "flask-route",
		TasksDir: "tasks",
		OutDir:   filepath.Join(t.TempDir(), "out"),
		HeldOut:  []string{"py-vulnerable-flask"},
		MockPatch: &processor.Patch{
			Decision:        "suppress_pattern",
			SuppressPattern: "(?i)admin_required",
			Rationale:       "test patch",
		},
		Out:      &out,
		RunTests: false,
	})
	require.NoError(t, err)
	require.Contains(t, out.String(), "Held-out: precision")
}

func TestPatchApplicationCompilesAndGateRuns(t *testing.T) {
	path := filepath.Join("..", "internal", "scanner", "matchers", "python.toml")
	body, err := os.ReadFile(path)
	require.NoError(t, err)
	patch := processor.Patch{Decision: "requires_tech", RequiresTech: []string{"flask"}, Rationale: "keep Flask-only route matcher scoped"}
	next, err := patchMatcherBytes(body, "flask-route", patch)
	require.NoError(t, err)
	require.NoError(t, compileMatcherFile(path, next))
	require.Contains(t, string(next), `requires = { tech = ["flask"] }`)
}
