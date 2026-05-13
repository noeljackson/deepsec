package commands

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/noeljackson/deepsec/internal/core"
	"github.com/stretchr/testify/require"
)

func TestRunHTMLReportProducesStaticSite(t *testing.T) {
	tmp := t.TempDir()
	out := filepath.Join(tmp, "site")
	records := []*core.FileRecord{
		{
			FilePath: "src/main.go",
			Findings: []core.Finding{
				{
					Severity:       core.SeverityHigh,
					VulnSlug:       "sql-injection",
					Title:          "Unparameterised query",
					Description:    "User input concatenated into a Postgres query.",
					Recommendation: "Use parameterised queries with pgx.",
					LineNumbers:    []int{42, 43},
					Confidence:     core.ConfidenceHigh,
				},
				{
					Severity:     core.SeverityMedium,
					VulnSlug:     "weak-crypto",
					Title:        "MD5 used for password hashing",
					Description:  "MD5 is fast and collidable.",
					LineNumbers:  []int{100},
					Confidence:   core.ConfidenceMedium,
					Revalidation: &core.Revalidation{Verdict: core.VerdictFalsePositive},
				},
			},
		},
		{
			FilePath: "src/util.go",
			Findings: []core.Finding{
				{
					Severity:    core.SeverityLow,
					VulnSlug:    "log-injection",
					Title:       "User input logged unsanitised",
					Description: "Newline injection possible.",
					LineNumbers: []int{17},
				},
			},
		},
	}
	require.NoError(t, runHTMLReport("test-project", records, core.SeverityLow, "", false, out))
	index, err := os.ReadFile(filepath.Join(out, "index.html"))
	require.NoError(t, err)
	body := string(index)
	require.Contains(t, body, "deepsec report")
	require.Contains(t, body, "test-project")
	require.Contains(t, body, "Unparameterised query")
	require.Contains(t, body, "MD5 used for password hashing")
	require.Contains(t, body, "User input logged unsanitised")
	require.Contains(t, body, `data-severity="HIGH"`)
	require.Contains(t, body, `data-severity="LOW"`)
	require.Contains(t, body, `data-verdict="false-positive"`)
	style, err := os.ReadFile(filepath.Join(out, "style.css"))
	require.NoError(t, err)
	require.Contains(t, string(style), ".sev-critical")
	entries, err := os.ReadDir(filepath.Join(out, "findings"))
	require.NoError(t, err)
	require.Len(t, entries, 3)
	// One detail page should mention the recommendation.
	var foundRec bool
	for _, e := range entries {
		body, err := os.ReadFile(filepath.Join(out, "findings", e.Name()))
		require.NoError(t, err)
		if strings.Contains(string(body), "Use parameterised queries") {
			foundRec = true
			break
		}
	}
	require.True(t, foundRec, "expected detail page with recommendation")
}

func TestRunHTMLReportRequiresOutputAndProjectID(t *testing.T) {
	require.Error(t, runHTMLReport("", nil, core.SeverityLow, "", false, "/tmp/out"))
	require.Error(t, runHTMLReport("p1", nil, core.SeverityLow, "", false, ""))
}

func TestRunHTMLReportHonoursMinSeverityAndRealOnly(t *testing.T) {
	tmp := t.TempDir()
	out := filepath.Join(tmp, "site")
	records := []*core.FileRecord{{
		FilePath: "x.go",
		Findings: []core.Finding{
			{Severity: core.SeverityLow, VulnSlug: "a", Title: "low one"},
			{Severity: core.SeverityHigh, VulnSlug: "b", Title: "high one",
				Revalidation: &core.Revalidation{Verdict: core.VerdictFalsePositive}},
			{Severity: core.SeverityHigh, VulnSlug: "c", Title: "real-high"},
		},
	}}
	require.NoError(t, runHTMLReport("p1", records, core.SeverityHigh, "", true, out))
	body, err := os.ReadFile(filepath.Join(out, "index.html"))
	require.NoError(t, err)
	require.NotContains(t, string(body), "low one")
	require.NotContains(t, string(body), "high one") // dropped: FP
	require.Contains(t, string(body), "real-high")
}
