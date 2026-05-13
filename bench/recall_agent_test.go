package bench

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/noeljackson/deepsec/internal/core"
	"github.com/noeljackson/deepsec/internal/processor"
	"github.com/stretchr/testify/require"
)

func TestParseNewMatcherStrictSchemaAcceptsValidProposal(t *testing.T) {
	body := `{
  "decision": "new_matcher",
  "slug": "java-xxe-docbuilder",
  "toml_body": "[[matcher]]\nslug = \"java-xxe-docbuilder\"\ndescription = \"XXE in DocumentBuilder\"\nnoise_tier = \"normal\"\nfile_patterns = [\"**/*.java\"]\npatterns = [\"DocumentBuilderFactory\"]\nlabel = \"xxe\"",
  "rationale": "DocumentBuilderFactory without disabling external entities"
}`
	m, err := processor.ParseNewMatcher(body)
	require.NoError(t, err)
	require.Equal(t, "new_matcher", m.Decision)
	require.Equal(t, "java-xxe-docbuilder", m.Slug)
	require.Contains(t, m.TOMLBody, "[[matcher]]")
}

func TestParseNewMatcherRejectsMissingFields(t *testing.T) {
	cases := []string{
		`{"decision": "new_matcher"}`,
		`{"decision": "new_matcher", "slug": "x"}`,
		`{"decision": "new_matcher", "slug": "x", "toml_body": "not a matcher block"}`,
		`{"decision": "cannot-fix"}`,
		`{"decision": "needs-engine-feature"}`,
		`{"decision": "garbage"}`,
	}
	for _, body := range cases {
		t.Run(body, func(t *testing.T) {
			_, err := processor.ParseNewMatcher(body)
			require.Error(t, err)
		})
	}
}

func TestPickWorstRecallClusterPrefersHighCritical(t *testing.T) {
	result := &RunResult{
		FalseNegatives: []FalseNegative{
			{TaskID: "t1", VulnSlugs: []string{"low-prio"}, Severity: core.SeverityLow},
			{TaskID: "t2", VulnSlugs: []string{"low-prio"}, Severity: core.SeverityLow},
			{TaskID: "t3", VulnSlugs: []string{"low-prio"}, Severity: core.SeverityLow},
			{TaskID: "t4", VulnSlugs: []string{"crit-bug"}, Severity: core.SeverityCritical},
			{TaskID: "t5", VulnSlugs: []string{"crit-bug"}, Severity: core.SeverityHigh},
		},
	}
	cluster, err := pickWorstRecallCluster(result, "")
	require.NoError(t, err)
	require.Equal(t, "crit-bug", cluster.VulnSlug)
	require.Len(t, cluster.FalseNegatives, 2)
}

func TestPickWorstRecallClusterEmpty(t *testing.T) {
	_, err := pickWorstRecallCluster(&RunResult{}, "")
	require.Error(t, err)
	require.Contains(t, err.Error(), "no false negatives")
}

func TestPickWorstRecallClusterExplicit(t *testing.T) {
	result := &RunResult{
		FalseNegatives: []FalseNegative{
			{TaskID: "t1", VulnSlugs: []string{"a"}, Severity: core.SeverityLow},
			{TaskID: "t2", VulnSlugs: []string{"b"}, Severity: core.SeverityCritical},
		},
	}
	cluster, err := pickWorstRecallCluster(result, "a")
	require.NoError(t, err)
	require.Equal(t, "a", cluster.VulnSlug)
}

func TestEvaluateRecallGateRequiresFNReduction(t *testing.T) {
	cluster := recallCluster{VulnSlug: "v", FalseNegatives: []FalseNegative{{}}}
	before := &RunResult{
		FalseNegatives: []FalseNegative{{VulnSlugs: []string{"v"}}},
		Summary:        Summary{CandidateCountTotal: 100},
	}
	after := &RunResult{
		FalseNegatives: []FalseNegative{{VulnSlugs: []string{"v"}}},
		Summary:        Summary{CandidateCountTotal: 100},
	}
	gate := EvaluateRecallGate(cluster, "new-slug", before, after, 0.05, 0.25)
	require.False(t, gate.Accepted)
	require.Contains(t, gate.Reasons[0], "did not reduce")
}

func TestEvaluateRecallGateAcceptsCleanProposal(t *testing.T) {
	cluster := recallCluster{VulnSlug: "v", FalseNegatives: []FalseNegative{{}}}
	before := &RunResult{
		FalseNegatives: []FalseNegative{{VulnSlugs: []string{"v"}}},
		BySlug:         []SlugResult{{Slug: "x", TruePositive: 10, CandidateCount: 10}},
		Summary:        Summary{CandidateCountTotal: 10},
	}
	after := &RunResult{
		FalseNegatives: nil,
		BySlug: []SlugResult{
			{Slug: "x", TruePositive: 10, CandidateCount: 10},
			{Slug: "new-slug", TruePositive: 1, CandidateCount: 1},
		},
		Summary: Summary{CandidateCountTotal: 11},
	}
	gate := EvaluateRecallGate(cluster, "new-slug", before, after, 0.5, 0.25)
	require.True(t, gate.Accepted, "reasons: %v", gate.Reasons)
}

func TestEvaluateRecallGateRejectsLowPrecision(t *testing.T) {
	cluster := recallCluster{VulnSlug: "v", FalseNegatives: []FalseNegative{{}}}
	before := &RunResult{
		FalseNegatives: []FalseNegative{{VulnSlugs: []string{"v"}}},
		Summary:        Summary{CandidateCountTotal: 0},
	}
	after := &RunResult{
		BySlug:  []SlugResult{{Slug: "new-slug", TruePositive: 1, CandidateCount: 20}},
		Summary: Summary{CandidateCountTotal: 0},
	}
	gate := EvaluateRecallGate(cluster, "new-slug", before, after, 0.5, 0.5)
	require.False(t, gate.Accepted)
	require.Contains(t, strings.Join(gate.Reasons, "\n"), "precision")
}

func TestEvaluateRecallGateRejectsCandidateBlowout(t *testing.T) {
	cluster := recallCluster{VulnSlug: "v", FalseNegatives: []FalseNegative{{}}}
	before := &RunResult{
		FalseNegatives: []FalseNegative{{VulnSlugs: []string{"v"}}},
		Summary:        Summary{CandidateCountTotal: 100},
	}
	after := &RunResult{
		BySlug:  []SlugResult{{Slug: "new-slug", TruePositive: 1, CandidateCount: 1000}},
		Summary: Summary{CandidateCountTotal: 1100},
	}
	gate := EvaluateRecallGate(cluster, "new-slug", before, after, 0.05, 0.25)
	require.False(t, gate.Accepted)
	require.Contains(t, strings.Join(gate.Reasons, "\n"), "candidate count grew")
}

func TestValidateProposalTOMLRejectsBadBlock(t *testing.T) {
	cases := []string{
		"",
		"not toml",
		`[[matcher]]
slug = "ok"`, // missing description, patterns, etc → Compile will fail
		`[[matcher]]
slug = "a"
description = ""
noise_tier = "normal"
patterns = []`,
	}
	for _, body := range cases {
		t.Run(body, func(t *testing.T) {
			require.Error(t, validateProposalTOML(body))
		})
	}
}

func TestValidateProposalTOMLAcceptsGoodBlock(t *testing.T) {
	body := `[[matcher]]
slug = "java-x"
description = "test"
noise_tier = "normal"
file_patterns = ["**/*.java"]
patterns = ["X"]
label = "x"`
	require.NoError(t, validateProposalTOML(body))
}

func TestWriteProposalToExtraDryRunUsesTempDir(t *testing.T) {
	proposal := processor.NewMatcher{
		Decision: "new_matcher",
		Slug:     "java-test-recall",
		TOMLBody: `[[matcher]]
slug = "java-test-recall"
description = "test"
noise_tier = "normal"
file_patterns = ["**/*.java"]
patterns = ["X"]
label = "x"`,
	}
	dir, cleanup, err := writeProposalToExtra(proposal, false)
	require.NoError(t, err)
	defer cleanup()
	require.NotEqual(t, extraMatchersDir, dir)
	contents, err := os.ReadFile(filepath.Join(dir, "java-test-recall.toml"))
	require.NoError(t, err)
	require.Contains(t, string(contents), "java-test-recall")
}

func TestRunRecallAgentDryRunWithMockProposal(t *testing.T) {
	// Skip if we're not in the repo (extraMatchersDir computation needs
	// the project layout).
	if _, err := os.Stat("./tasks"); err != nil {
		t.Skip("recall agent test requires bench/tasks present")
	}
	mock := processor.NewMatcher{
		Decision:  "new_matcher",
		Slug:      "test-recall-mock-slug",
		Rationale: "stub matcher for the recall agent dry-run test",
		TOMLBody: `[[matcher]]
slug = "test-recall-mock-slug"
description = "test stub"
noise_tier = "normal"
file_patterns = ["**/*.never-matches"]
patterns = ["never"]
label = "stub"`,
	}
	buf := &bytes.Buffer{}
	err := RunRecallAgent(context.Background(), RecallAgentOptions{
		MockProposal: &mock,
		Apply:        false,
		TasksDir:     "tasks",
		OutDir:       t.TempDir(),
		Out:          buf,
	})
	// Will likely "reject" the proposal since the stub catches no FNs,
	// but the loop should run without panicking — that's the contract
	// we care about here. The gate-level tests above cover acceptance.
	if err != nil {
		require.Contains(t, err.Error(), "false negative", "unexpected error: %v", err)
	}
	require.NotEmpty(t, buf.String())
}
