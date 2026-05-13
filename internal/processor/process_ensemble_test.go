package processor

import (
	"testing"

	"github.com/noeljackson/deepsec/internal/core"
	"github.com/stretchr/testify/require"
)

func TestFindingIdentityStableAcrossWhitespaceAndCase(t *testing.T) {
	a := &core.Finding{
		VulnSlug:    "sql-injection",
		Title:       "SQL Injection in handler",
		LineNumbers: []int{42, 43},
	}
	b := &core.Finding{
		VulnSlug:    "sql-injection",
		Title:       "sql   injection  IN  HANDLER",
		LineNumbers: []int{43, 42},
	}
	require.Equal(t, findingIdentity(a), findingIdentity(b))
}

func TestFindingIdentityDifferentSlugDiffers(t *testing.T) {
	a := &core.Finding{VulnSlug: "sql-injection", Title: "x"}
	b := &core.Finding{VulnSlug: "ssrf", Title: "x"}
	require.NotEqual(t, findingIdentity(a), findingIdentity(b))
}

func TestMergeEnsembleAgreementTagsConsensus(t *testing.T) {
	dr := core.DataRootFromPath(t.TempDir())
	_, err := dr.EnsureProject("p1", t.TempDir(), "")
	require.NoError(t, err)
	rec := &core.FileRecord{
		FilePath:  "main.go",
		ProjectID: "p1",
		Findings: []core.Finding{
			{Severity: core.SeverityHigh, VulnSlug: "sqli", Title: "Unparameterised query",
				LineNumbers: []int{42}, ProducedByRunID: "run-anthropic"},
			{Severity: core.SeverityHigh, VulnSlug: "sqli", Title: "Unparameterised query",
				LineNumbers: []int{42}, ProducedByRunID: "run-openai"},
			{Severity: core.SeverityMedium, VulnSlug: "redos", Title: "ReDoS risk",
				LineNumbers: []int{100}, ProducedByRunID: "run-anthropic"},
		},
	}
	require.NoError(t, dr.WriteFileRecord(rec))

	out := &EnsembleOutcome{
		AgentByRunID: map[string]string{
			"run-anthropic": "anthropic",
			"run-openai":    "openai",
		},
	}
	require.NoError(t, mergeEnsembleAgreement(dr, "p1", out))

	got, err := dr.ReadFileRecord("p1", "main.go")
	require.NoError(t, err)
	// 2 unique findings: sqli (consensus by 2) + redos (solo by anthropic)
	require.Len(t, got.Findings, 2)
	require.Equal(t, []string{"anthropic", "openai"}, got.Findings[0].AgreeingAgents)
	require.Equal(t, []string{"anthropic"}, got.Findings[1].AgreeingAgents)
	require.Equal(t, 2, out.UniqueFindings)
	require.Equal(t, 1, out.ConsensusCount)
	require.Equal(t, 1, out.SoloCount)
}

func TestMergeEnsembleAgreementIgnoresUnrelatedRuns(t *testing.T) {
	dr := core.DataRootFromPath(t.TempDir())
	_, err := dr.EnsureProject("p1", t.TempDir(), "")
	require.NoError(t, err)
	rec := &core.FileRecord{
		FilePath:  "main.go",
		ProjectID: "p1",
		Findings: []core.Finding{
			// from a prior single-agent run, NOT part of this ensemble
			{Severity: core.SeverityHigh, VulnSlug: "sqli", Title: "Old finding",
				LineNumbers: []int{42}, ProducedByRunID: "ancient-run"},
		},
	}
	require.NoError(t, dr.WriteFileRecord(rec))

	out := &EnsembleOutcome{
		AgentByRunID: map[string]string{"run-x": "x", "run-y": "y"},
	}
	require.NoError(t, mergeEnsembleAgreement(dr, "p1", out))
	got, err := dr.ReadFileRecord("p1", "main.go")
	require.NoError(t, err)
	require.Len(t, got.Findings, 1, "ancient finding should be untouched")
	require.Empty(t, got.Findings[0].AgreeingAgents)
	require.Equal(t, 0, out.UniqueFindings)
}

func TestResetPendingForReinvestigation(t *testing.T) {
	dr := core.DataRootFromPath(t.TempDir())
	_, err := dr.EnsureProject("p1", t.TempDir(), "")
	require.NoError(t, err)
	require.NoError(t, dr.WriteFileRecord(&core.FileRecord{
		FilePath:  "a.go",
		ProjectID: "p1",
		Status:    core.StatusAnalyzed,
	}))
	require.NoError(t, dr.WriteFileRecord(&core.FileRecord{
		FilePath:  "b.go",
		ProjectID: "p1",
		Status:    core.StatusError,
	}))
	require.NoError(t, resetPendingForReinvestigation(dr, "p1"))

	a, _ := dr.ReadFileRecord("p1", "a.go")
	require.Equal(t, core.StatusPending, a.Status)
	b, _ := dr.ReadFileRecord("p1", "b.go")
	require.Equal(t, core.StatusError, b.Status, "non-analyzed status should be left alone")
}
