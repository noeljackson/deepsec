package core

import (
	"encoding/json"
	"testing"

	"github.com/stretchr/testify/require"
)

// Wire-compatibility checks. These freeze the on-disk JSON shape so a
// future refactor can't silently break data directories.

func TestFileRecordRoundtripsCamelCaseFields(t *testing.T) {
	const body = `{
      "filePath": "src/api/users.ts",
      "projectId": "p",
      "candidates": [{
        "vulnSlug": "sql-injection-string-concat",
        "lineNumbers": [42, 43],
        "snippet": "let x = q",
        "matchedPattern": "SQL injection"
      }],
      "lastScannedAt": "2026-05-11T00:00:00Z",
      "lastScannedRunId": "20260511000000-aaaa",
      "fileHash": "deadbeef",
      "findings": [{
        "severity": "HIGH",
        "vulnSlug": "sql-injection-string-concat",
        "title": "T",
        "description": "D",
        "lineNumbers": [42],
        "recommendation": "Use parameterized queries",
        "confidence": "high",
        "producedByRunId": "20260511000000-aaaa"
      }],
      "analysisHistory": [{
        "runId": "20260511000000-aaaa",
        "investigatedAt": "2026-05-11T00:01:00Z",
        "durationMs": 1234,
        "agentType": "anthropic",
        "model": "claude-sonnet-4-6",
        "modelConfig": {},
        "findingCount": 1,
        "phase": "process",
        "costUsd": 0.01,
        "usage": {
          "inputTokens": 100,
          "outputTokens": 50,
          "cacheReadInputTokens": 0,
          "cacheCreationInputTokens": 0
        }
      }],
      "status": "analyzed"
    }`
	var rec FileRecord
	require.NoError(t, json.Unmarshal([]byte(body), &rec))
	require.Equal(t, "src/api/users.ts", rec.FilePath)
	require.Len(t, rec.Candidates, 1)
	require.Equal(t, "sql-injection-string-concat", rec.Candidates[0].VulnSlug)
	require.Len(t, rec.Findings, 1)
	require.Equal(t, SeverityHigh, rec.Findings[0].Severity)
	require.Equal(t, ConfidenceHigh, rec.Findings[0].Confidence)
	require.Equal(t, StatusAnalyzed, rec.Status)
	entry := rec.AnalysisHistory[0]
	require.Equal(t, PhaseProcess, entry.Phase)
	require.NotNil(t, entry.CostUSD)
	require.Equal(t, 0.01, *entry.CostUSD)
	require.NotNil(t, entry.Usage)
	require.Equal(t, uint64(100), entry.Usage.InputTokens)

	// Re-serialize and re-parse; must be lossless.
	body2, err := json.Marshal(rec)
	require.NoError(t, err)
	var rec2 FileRecord
	require.NoError(t, json.Unmarshal(body2, &rec2))
	require.Equal(t, rec.FilePath, rec2.FilePath)
	require.Equal(t, rec.Candidates[0].VulnSlug, rec2.Candidates[0].VulnSlug)
}

func TestFindingSerializesWithCamelCaseFieldNames(t *testing.T) {
	f := Finding{
		Severity:        SeverityCritical,
		VulnSlug:        "x",
		Title:           "T",
		Description:     "D",
		LineNumbers:     []int{1},
		Recommendation:  "R",
		Confidence:      ConfidenceMedium,
		ProducedByRunID: "r",
	}
	body, err := json.Marshal(f)
	require.NoError(t, err)
	s := string(body)
	require.Contains(t, s, `"vulnSlug"`)
	require.Contains(t, s, `"lineNumbers"`)
	require.Contains(t, s, `"producedByRunId"`)
	require.Contains(t, s, `"severity":"CRITICAL"`)
	require.Contains(t, s, `"confidence":"medium"`)
}

func TestRunMetaAcceptsCamelCaseLayout(t *testing.T) {
	const body = `{
      "runId": "20260511000000-aaaa",
      "projectId": "p",
      "rootPath": "./app",
      "createdAt": "2026-05-11T00:00:00Z",
      "type": "process",
      "phase": "done",
      "scannerConfig": {
        "matcherSlugs": ["a", "b"],
        "mode": "full"
      },
      "processorConfig": {
        "agentType": "anthropic",
        "model": "claude-sonnet-4-6",
        "modelConfig": {},
        "invocationMode": "scan"
      },
      "stats": {
        "filesScanned": 10,
        "candidatesFound": 5,
        "filesProcessed": 5,
        "findingsCount": 2,
        "totalCostUsd": 0.05,
        "totalInputTokens": 1000,
        "totalOutputTokens": 500,
        "totalDurationMs": 12345
      }
    }`
	var m RunMeta
	require.NoError(t, json.Unmarshal([]byte(body), &m))
	require.Equal(t, "20260511000000-aaaa", m.RunID)
	require.Equal(t, 10, *m.Stats.FilesScanned)
	require.Equal(t, 0.05, *m.Stats.TotalCostUSD)
	require.Len(t, m.ScannerConfig.MatcherSlugs, 2)
}

func TestProjectConfigCamelCaseRoundtrip(t *testing.T) {
	p := ProjectConfig{
		ProjectID: "p",
		RootPath:  "./app",
		CreatedAt: "2026-05-11T00:00:00Z",
		GithubURL: "https://github.com/o/r/blob/main",
	}
	body, err := json.Marshal(p)
	require.NoError(t, err)
	s := string(body)
	require.Contains(t, s, `"projectId"`)
	require.Contains(t, s, `"rootPath"`)
	require.Contains(t, s, `"createdAt"`)
	require.Contains(t, s, `"githubUrl"`)
	var back ProjectConfig
	require.NoError(t, json.Unmarshal(body, &back))
	require.Equal(t, p, back)
}

func TestLegacyAnalysisEntryWithoutPhaseStillParses(t *testing.T) {
	const body = `{
      "runId": "old",
      "investigatedAt": "2026-01-01T00:00:00Z",
      "durationMs": 0,
      "agentType": "anthropic",
      "model": "m",
      "modelConfig": {},
      "findingCount": 0
    }`
	var a AnalysisEntry
	require.NoError(t, json.Unmarshal([]byte(body), &a))
	require.Equal(t, AnalysisPhase(""), a.Phase)
	require.Nil(t, a.CostUSD)
	require.Nil(t, a.Usage)
}

func TestSeverityRankOrdering(t *testing.T) {
	require.Greater(t, SeverityCritical.Rank(), SeverityHigh.Rank())
	require.Greater(t, SeverityHigh.Rank(), SeverityMedium.Rank())
	require.Greater(t, SeverityMedium.Rank(), SeverityLow.Rank())
}

func TestUsageDefaultsZero(t *testing.T) {
	var u Usage
	require.NoError(t, json.Unmarshal([]byte(`{}`), &u))
	require.Equal(t, uint64(0), u.InputTokens)
	require.Equal(t, uint64(0), u.OutputTokens)
	require.Equal(t, uint64(0), u.CacheReadInputTokens)
}
