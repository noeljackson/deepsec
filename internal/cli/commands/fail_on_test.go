package commands

import (
	"path/filepath"
	"testing"

	"github.com/noeljackson/deepsec/internal/cli"
	"github.com/noeljackson/deepsec/internal/core"
	"github.com/stretchr/testify/require"
)

func scaffoldFailOnProject(t *testing.T, findings []core.Finding) *cli.Context {
	t.Helper()
	dr := core.DataRootFromPath(t.TempDir())
	src := filepath.Join(t.TempDir(), "src")
	_, err := dr.EnsureProject("p1", src, "")
	require.NoError(t, err)
	rec := &core.FileRecord{
		FilePath:  "main.go",
		ProjectID: "p1",
		Findings:  findings,
	}
	require.NoError(t, dr.WriteFileRecord(rec))
	return &cli.Context{DataRoot: dr}
}

func TestEnforceFailOnHighTriggersOnHighFinding(t *testing.T) {
	runID := "run-1"
	ctx := scaffoldFailOnProject(t, []core.Finding{
		{Severity: core.SeverityHigh, VulnSlug: "sqli", Title: "x", ProducedByRunID: runID},
	})
	err := enforceFailOn(ctx, "p1", runID, "HIGH")
	require.Error(t, err)
	require.Contains(t, err.Error(), "at or above HIGH")
}

func TestEnforceFailOnHighSilentOnMediumFinding(t *testing.T) {
	runID := "run-1"
	ctx := scaffoldFailOnProject(t, []core.Finding{
		{Severity: core.SeverityMedium, VulnSlug: "x", Title: "x", ProducedByRunID: runID},
	})
	require.NoError(t, enforceFailOn(ctx, "p1", runID, "HIGH"))
}

func TestEnforceFailOnIgnoresRevalidatedFP(t *testing.T) {
	runID := "run-1"
	ctx := scaffoldFailOnProject(t, []core.Finding{
		{
			Severity:        core.SeverityCritical,
			VulnSlug:        "x",
			Title:           "x",
			ProducedByRunID: runID,
			Revalidation:    &core.Revalidation{Verdict: core.VerdictFalsePositive},
		},
	})
	require.NoError(t, enforceFailOn(ctx, "p1", runID, "HIGH"))
}

func TestEnforceFailOnRejectsBadThreshold(t *testing.T) {
	ctx := scaffoldFailOnProject(t, nil)
	err := enforceFailOn(ctx, "p1", "run-1", "WARNING")
	require.Error(t, err)
	require.Contains(t, err.Error(), "unknown severity")
}

func TestEnforceFailOnRunIDScoping(t *testing.T) {
	ctx := scaffoldFailOnProject(t, []core.Finding{
		{Severity: core.SeverityHigh, VulnSlug: "x", ProducedByRunID: "older-run"},
	})
	require.NoError(t, enforceFailOn(ctx, "p1", "run-2", "HIGH"))
	require.Error(t, enforceFailOn(ctx, "p1", "older-run", "HIGH"))
}
