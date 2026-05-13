package processor

import (
	"strings"
	"testing"

	"github.com/noeljackson/deepsec/internal/core"
	"github.com/stretchr/testify/require"
)

func TestApplySkepticVerdictsDropsFalsePositive(t *testing.T) {
	findings := []ProducedFinding{
		{Severity: core.SeverityHigh, VulnSlug: "sql-injection", Title: "SQLi"},
		{Severity: core.SeverityHigh, VulnSlug: "ssrf", Title: "SSRF"},
	}
	verdicts := []RevalidatedFinding{
		{Index: 0, Verdict: core.VerdictFalsePositive, Reasoning: "input is type-safe int"},
		{Index: 1, Verdict: core.VerdictTruePositive, Reasoning: "no allowlist"},
	}
	out := applySkepticVerdicts(findings, verdicts)
	require.Len(t, out, 1)
	require.Equal(t, "ssrf", out[0].VulnSlug)
	require.Contains(t, out[0].Description, "survived skeptic")
}

func TestApplySkepticVerdictsDropsFixed(t *testing.T) {
	findings := []ProducedFinding{{Severity: core.SeverityHigh, VulnSlug: "xss", Title: "XSS"}}
	verdicts := []RevalidatedFinding{{Index: 0, Verdict: core.VerdictFixed, Reasoning: "framework escapes by default"}}
	out := applySkepticVerdicts(findings, verdicts)
	require.Len(t, out, 0)
}

func TestApplySkepticVerdictsDemotesUncertain(t *testing.T) {
	findings := []ProducedFinding{{Severity: core.SeverityHigh, VulnSlug: "redos", Title: "ReDoS"}}
	verdicts := []RevalidatedFinding{{Index: 0, Verdict: core.VerdictUncertain, Reasoning: "complex regex; can't tell"}}
	out := applySkepticVerdicts(findings, verdicts)
	require.Len(t, out, 1)
	require.Equal(t, core.SeverityLow, out[0].Severity)
	require.Contains(t, out[0].Description, "demoted by skeptic")
}

func TestApplySkepticVerdictsAppliesAdjustedSeverity(t *testing.T) {
	med := core.SeverityMedium
	findings := []ProducedFinding{{Severity: core.SeverityHigh, VulnSlug: "log-injection", Title: "Log inj"}}
	verdicts := []RevalidatedFinding{{
		Index: 0, Verdict: core.VerdictTruePositive,
		Reasoning:        "exploitable but limited blast radius — log only",
		AdjustedSeverity: &med,
	}}
	out := applySkepticVerdicts(findings, verdicts)
	require.Len(t, out, 1)
	require.Equal(t, core.SeverityMedium, out[0].Severity)
}

func TestApplySkepticVerdictsKeepsFindingWithoutVerdict(t *testing.T) {
	findings := []ProducedFinding{
		{Severity: core.SeverityHigh, VulnSlug: "a"},
		{Severity: core.SeverityHigh, VulnSlug: "b"},
	}
	// Only the first finding has a verdict; the second should be kept
	// unchanged rather than silently dropped.
	verdicts := []RevalidatedFinding{{Index: 0, Verdict: core.VerdictTruePositive}}
	out := applySkepticVerdicts(findings, verdicts)
	require.Len(t, out, 2)
}

func TestBuildRevalidatePromptSkepticVariant(t *testing.T) {
	in := &RevalidateInput{
		FilePath:    "main.go",
		FileContent: "package main\n",
		Findings: []RevalidateInputFinding{
			{Index: 0, Severity: core.SeverityHigh, VulnSlug: "sqli", Title: "SQLi"},
		},
		Skeptic: true,
	}
	system, _ := BuildRevalidatePrompt(in)
	require.Contains(t, strings.ToLower(system), "skeptic", "skeptic prompt missing stance marker")
	require.Contains(t, strings.ToLower(system), "disprove")
}

func TestBuildRevalidatePromptDefaultVariant(t *testing.T) {
	in := &RevalidateInput{FilePath: "main.go"}
	system, _ := BuildRevalidatePrompt(in)
	require.NotContains(t, strings.ToLower(system), "disprove")
}
