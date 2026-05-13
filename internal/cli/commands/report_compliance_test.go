package commands

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/noeljackson/deepsec/internal/core"
	"github.com/stretchr/testify/require"
)

func sampleRecord() *core.FileRecord {
	return &core.FileRecord{
		FilePath:         "src/app.ts",
		ProjectID:        "p",
		FileHash:         "deadbeef",
		LastScannedAt:    "2026-05-13T00:00:00Z",
		LastScannedRunID: "20260513000000-aaaa",
		AnalysisHistory: []core.AnalysisEntry{
			{
				RunID:          "20260513000000-aaaa",
				InvestigatedAt: "2026-05-13T00:01:00Z",
				AgentType:      "anthropic",
				Model:          "claude-sonnet-4-6",
			},
		},
		Findings: []core.Finding{
			{
				Severity:        core.SeverityHigh,
				VulnSlug:        "ssrf",
				Title:           "SSRF",
				Description:     "...",
				Recommendation:  "validate URL",
				LineNumbers:     []int{12, 13},
				Confidence:      core.ConfidenceHigh,
				ProducedByRunID: "20260513000000-aaaa",
			},
		},
	}
}

func TestBuildComplianceReportPopulatesManifest(t *testing.T) {
	rec := sampleRecord()
	rep, err := BuildComplianceReport("soc2", "p", []*core.FileRecord{rec}, nil)
	require.NoError(t, err)
	require.Equal(t, "soc2", rep.Format)
	require.Equal(t, "1.0", rep.SchemaVersion)
	require.NotEmpty(t, rep.Manifest.MatcherPackHash)
	require.NotEmpty(t, rep.Manifest.PromptPackHash)
	require.Contains(t, rep.Manifest.Providers, "anthropic")
	require.Contains(t, rep.Manifest.Models, "claude-sonnet-4-6")
	require.Equal(t, 1, rep.Manifest.FindingsCount)
	require.Len(t, rep.Findings, 1)
	f := rep.Findings[0]
	require.Equal(t, "ssrf", f.VulnSlug)
	require.Equal(t, "open", f.Status)
	require.NotEmpty(t, f.FindingID)
	require.NotEmpty(t, f.EvidenceHash)
	require.Equal(t, "anthropic", f.Provider)
	require.Equal(t, "claude-sonnet-4-6", f.Model)
}

func TestStableFindingIDIsDeterministic(t *testing.T) {
	f := &core.Finding{VulnSlug: "ssrf", LineNumbers: []int{12, 13}}
	id1 := stableFindingID("src/app.ts", f)
	id2 := stableFindingID("src/app.ts", f)
	require.Equal(t, id1, id2)

	f2 := &core.Finding{VulnSlug: "ssrf", LineNumbers: []int{12, 14}}
	require.NotEqual(t, id1, stableFindingID("src/app.ts", f2),
		"different lines should produce different ids")
}

func TestEvidenceHashTiesToFileHash(t *testing.T) {
	f := &core.Finding{VulnSlug: "ssrf", LineNumbers: []int{12}, ProducedByRunID: "r1"}
	h1 := evidenceHash("src/app.ts", f, "hashA")
	h2 := evidenceHash("src/app.ts", f, "hashB")
	require.NotEqual(t, h1, h2, "evidence hash must change when file content changes")
}

func TestSignAndVerifyRoundTrip(t *testing.T) {
	rep, err := BuildComplianceReport("soc2", "p", []*core.FileRecord{sampleRecord()}, nil)
	require.NoError(t, err)
	key := []byte("test-key-please-rotate")
	require.NoError(t, SignComplianceReport(rep, key))
	require.NotNil(t, rep.Signature)
	require.Equal(t, "HMAC-SHA256", rep.Signature.Algorithm)
	require.Len(t, rep.Signature.Value, 64)
	require.NoError(t, VerifyComplianceReport(rep, key))
}

func TestVerifyRejectsTamperedReport(t *testing.T) {
	rep, err := BuildComplianceReport("soc2", "p", []*core.FileRecord{sampleRecord()}, nil)
	require.NoError(t, err)
	key := []byte("test-key")
	require.NoError(t, SignComplianceReport(rep, key))

	// Tamper with a finding after signing.
	rep.Findings[0].Severity = "LOW"
	require.Error(t, VerifyComplianceReport(rep, key))
}

func TestVerifyRejectsWrongKey(t *testing.T) {
	rep, err := BuildComplianceReport("soc2", "p", []*core.FileRecord{sampleRecord()}, nil)
	require.NoError(t, err)
	require.NoError(t, SignComplianceReport(rep, []byte("alpha")))
	require.Error(t, VerifyComplianceReport(rep, []byte("bravo")))
}

func TestVerifyRejectsUnsignedReport(t *testing.T) {
	rep, err := BuildComplianceReport("soc2", "p", []*core.FileRecord{sampleRecord()}, nil)
	require.NoError(t, err)
	require.Error(t, VerifyComplianceReport(rep, []byte("any")))
}

func TestWriteAndVerifyOnDisk(t *testing.T) {
	tmp := t.TempDir()
	path := filepath.Join(tmp, "compliance.json")
	rep, err := BuildComplianceReport("soc2", "p", []*core.FileRecord{sampleRecord()}, nil)
	require.NoError(t, err)
	t.Setenv("DEEPSEC_REPORT_SIGNING_KEY", "round-trip-key")
	require.NoError(t, writeComplianceReport(rep, path))

	// Read it back and re-verify.
	require.NoError(t, verifyComplianceFile(path, []byte("round-trip-key")))

	// Confirm the JSON is structured.
	body, err := os.ReadFile(path)
	require.NoError(t, err)
	var parsed ComplianceReport
	require.NoError(t, json.Unmarshal(body, &parsed))
	require.Equal(t, "1.0", parsed.SchemaVersion)
	require.NotNil(t, parsed.Signature)
}
