package processor

import (
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/noeljackson/deepsec/internal/core"
	"github.com/stretchr/testify/require"
)

type env struct {
	tmp         string
	dataRoot    core.DataRoot
	projectRoot string
	projectID   string
}

func newEnv(t *testing.T) *env {
	t.Helper()
	tmp := t.TempDir()
	dataRoot := core.DataRootFromPath(filepath.Join(tmp, "data"))
	projectRoot := filepath.Join(tmp, "app")
	require.NoError(t, os.MkdirAll(projectRoot, 0o755))
	_, err := dataRoot.EnsureProject("p", projectRoot, "")
	require.NoError(t, err)
	return &env{tmp: tmp, dataRoot: dataRoot, projectRoot: projectRoot, projectID: "p"}
}

func (e *env) writeSource(t *testing.T, rel, content string) {
	t.Helper()
	p := filepath.Join(e.projectRoot, rel)
	require.NoError(t, os.MkdirAll(filepath.Dir(p), 0o755))
	require.NoError(t, os.WriteFile(p, []byte(content), 0o644))
}

func (e *env) seedRecord(t *testing.T, rel string, status core.FileStatus, slug string) *core.FileRecord {
	t.Helper()
	e.writeSource(t, rel, "// dummy source\nlet x = 1;\n")
	rec := &core.FileRecord{
		FilePath:         rel,
		ProjectID:        e.projectID,
		Candidates:       []core.CandidateMatch{{VulnSlug: slug, LineNumbers: []int{1}, Snippet: "let x = 1;", MatchedPattern: "test"}},
		LastScannedAt:    "2026-01-01T00:00:00Z",
		LastScannedRunID: "seed-run",
		FileHash:         "abc",
		Status:           status,
	}
	require.NoError(t, e.dataRoot.WriteFileRecord(rec))
	return rec
}

func (e *env) readBack(t *testing.T, rel string) *core.FileRecord {
	t.Helper()
	rec, err := e.dataRoot.ReadFileRecord(e.projectID, rel)
	require.NoError(t, err)
	require.NotNil(t, rec)
	return rec
}

func baseOpts(e *env, m *MockBackend) ProcessOptions {
	return ProcessOptions{
		ProjectID:    e.projectID,
		ProjectRoot:  e.projectRoot,
		DataRoot:     e.dataRoot,
		Backend:      m,
		ProviderName: "anthropic",
		BatchSize:    2,
		Concurrency:  2,
	}
}

func TestProcessWritesFindingsAndMarksAnalyzed(t *testing.T) {
	e := newEnv(t)
	e.seedRecord(t, "src/a.ts", core.StatusPending, "mock-slug")
	e.seedRecord(t, "src/b.ts", core.StatusPending, "mock-slug")

	m := NewMockBackend()
	out, err := Process(context.Background(), baseOpts(e, m))
	require.NoError(t, err)
	require.Equal(t, 2, out.AnalysisCount)
	require.Equal(t, 2, out.FindingCount)
	require.False(t, out.QuotaExhausted)

	for _, path := range []string{"src/a.ts", "src/b.ts"} {
		rec := e.readBack(t, path)
		require.Equal(t, core.StatusAnalyzed, rec.Status, path)
		require.Len(t, rec.Findings, 1)
		require.Equal(t, "mock-slug", rec.Findings[0].VulnSlug)
		require.Equal(t, out.RunID, rec.Findings[0].ProducedByRunID)
		require.Len(t, rec.AnalysisHistory, 1)
		require.Equal(t, core.PhaseProcess, rec.AnalysisHistory[0].Phase)
		require.Empty(t, rec.LockedByRunID)
	}
	require.Equal(t, 1, m.InvestigateCalls())
}

func TestProcessSkipsAnalyzedFiles(t *testing.T) {
	e := newEnv(t)
	e.seedRecord(t, "src/a.ts", core.StatusAnalyzed, "mock-slug")
	e.seedRecord(t, "src/b.ts", core.StatusPending, "mock-slug")
	out, err := Process(context.Background(), baseOpts(e, NewMockBackend()))
	require.NoError(t, err)
	require.Equal(t, 1, out.AnalysisCount)
	require.Empty(t, e.readBack(t, "src/a.ts").Findings)
	require.Len(t, e.readBack(t, "src/b.ts").Findings, 1)
}

func TestProcessFilterPrefixNarrowsWork(t *testing.T) {
	e := newEnv(t)
	e.seedRecord(t, "src/api/a.ts", core.StatusPending, "mock-slug")
	e.seedRecord(t, "src/lib/b.ts", core.StatusPending, "mock-slug")
	opts := baseOpts(e, NewMockBackend())
	opts.FilterPrefix = "src/api/"
	out, err := Process(context.Background(), opts)
	require.NoError(t, err)
	require.Equal(t, 1, out.AnalysisCount)
	require.NotEmpty(t, e.readBack(t, "src/api/a.ts").Findings)
	require.Empty(t, e.readBack(t, "src/lib/b.ts").Findings)
}

func TestProcessOnlySlugsFiltersCandidates(t *testing.T) {
	e := newEnv(t)
	e.seedRecord(t, "src/a.ts", core.StatusPending, "wanted-slug")
	e.seedRecord(t, "src/b.ts", core.StatusPending, "other-slug")
	opts := baseOpts(e, NewMockBackend())
	opts.OnlySlugs = []string{"wanted-slug"}
	out, err := Process(context.Background(), opts)
	require.NoError(t, err)
	require.Equal(t, 1, out.AnalysisCount)
}

func TestProcessLimitCapsFiles(t *testing.T) {
	e := newEnv(t)
	for i := 0; i < 5; i++ {
		e.seedRecord(t, "src/f"+string(rune('0'+i))+".ts", core.StatusPending, "mock-slug")
	}
	opts := baseOpts(e, NewMockBackend())
	opts.Limit = 2
	out, err := Process(context.Background(), opts)
	require.NoError(t, err)
	require.Equal(t, 2, out.AnalysisCount)
}

func TestProcessQuotaReleasesLocksToPending(t *testing.T) {
	e := newEnv(t)
	for i := 0; i < 6; i++ {
		e.seedRecord(t, "src/f"+string(rune('0'+i))+".ts", core.StatusPending, "mock-slug")
	}
	m := NewMockBackend()
	m.QuotaAfter = 1
	opts := baseOpts(e, m)
	opts.BatchSize = 1
	opts.Concurrency = 1
	out, err := Process(context.Background(), opts)
	require.NoError(t, err)
	require.True(t, out.QuotaExhausted)
	require.GreaterOrEqual(t, out.AnalysisCount, 1)

	pending, analyzed := 0, 0
	for i := 0; i < 6; i++ {
		rec := e.readBack(t, "src/f"+string(rune('0'+i))+".ts")
		switch rec.Status {
		case core.StatusPending:
			pending++
		case core.StatusAnalyzed:
			analyzed++
		default:
			t.Fatalf("unexpected status %q on f%d", rec.Status, i)
		}
		require.Empty(t, rec.LockedByRunID)
	}
	require.GreaterOrEqual(t, pending, 1)
	require.GreaterOrEqual(t, analyzed, 1)
}

func TestProcessRefusalRecordsIntoHistory(t *testing.T) {
	e := newEnv(t)
	e.seedRecord(t, "src/a.ts", core.StatusPending, "mock-slug")
	m := NewMockBackend()
	m.ReturnRefusal = true
	out, err := Process(context.Background(), baseOpts(e, m))
	require.NoError(t, err)
	require.Equal(t, 0, out.AnalysisCount) // refusal isn't counted as a successful analysis

	rec := e.readBack(t, "src/a.ts")
	require.Equal(t, core.StatusError, rec.Status)
	require.Len(t, rec.AnalysisHistory, 1)
	require.NotNil(t, rec.AnalysisHistory[0].Refusal)
	require.True(t, rec.AnalysisHistory[0].Refusal.Refused)
}

func TestProcessConcurrencyRunsInParallel(t *testing.T) {
	e := newEnv(t)
	for i := 0; i < 8; i++ {
		e.seedRecord(t, "src/f"+string(rune('0'+i))+".ts", core.StatusPending, "mock-slug")
	}
	m := NewMockBackend()
	m.Delay = 200 * time.Millisecond
	opts := baseOpts(e, m)
	opts.BatchSize = 1
	opts.Concurrency = 8

	start := time.Now()
	out, err := Process(context.Background(), opts)
	require.NoError(t, err)
	elapsed := time.Since(start)
	require.Equal(t, 8, out.AnalysisCount)
	// Serial would be 8 * 200ms = 1600ms. Parallel should be ~200ms +
	// overhead. <800ms gives a comfortable margin while still catching
	// a regression to serial execution.
	require.Less(t, elapsed, 800*time.Millisecond, "expected parallel batches")
}

func TestProcessDirectModeProcessesAnalyzedFiles(t *testing.T) {
	e := newEnv(t)
	e.seedRecord(t, "src/a.ts", core.StatusAnalyzed, "mock-slug")
	e.seedRecord(t, "src/b.ts", core.StatusPending, "mock-slug")

	opts := baseOpts(e, NewMockBackend())
	opts.DirectFiles = []string{"src/a.ts"}
	opts.DirectSource = "test:direct"
	out, err := Process(context.Background(), opts)
	require.NoError(t, err)
	require.Equal(t, 1, out.AnalysisCount)
	require.NotEmpty(t, e.readBack(t, "src/a.ts").Findings)
	require.Empty(t, e.readBack(t, "src/b.ts").Findings)
}

func TestProcessReinvestigateSkipsSameWave(t *testing.T) {
	e := newEnv(t)
	rec := e.seedRecord(t, "src/a.ts", core.StatusPending, "mock-slug")
	one := 1
	rec.AnalysisHistory = append(rec.AnalysisHistory, core.AnalysisEntry{
		RunID:             "old-run",
		InvestigatedAt:    "2026-01-01T00:00:00Z",
		AgentType:         "anthropic",
		Model:             "mock",
		Phase:             core.PhaseProcess,
		ReinvestigateMark: &one,
	})
	require.NoError(t, e.dataRoot.WriteFileRecord(rec))

	opts := baseOpts(e, NewMockBackend())
	opts.ReinvestigateMark = 1
	out, err := Process(context.Background(), opts)
	require.NoError(t, err)
	require.Equal(t, 0, out.AnalysisCount)

	// Wave 2 should pick it up.
	rec = e.readBack(t, "src/a.ts")
	rec.Status = core.StatusPending
	require.NoError(t, e.dataRoot.WriteFileRecord(rec))
	opts.ReinvestigateMark = 2
	out, err = Process(context.Background(), opts)
	require.NoError(t, err)
	require.Equal(t, 1, out.AnalysisCount)
	rec = e.readBack(t, "src/a.ts")
	var found bool
	for _, e := range rec.AnalysisHistory {
		if e.ReinvestigateMark != nil && *e.ReinvestigateMark == 2 {
			found = true
		}
	}
	require.True(t, found)
}

func TestRevalidateAssignsVerdictToExisting(t *testing.T) {
	e := newEnv(t)
	rec := e.seedRecord(t, "src/a.ts", core.StatusAnalyzed, "mock-slug")
	rec.Findings = append(rec.Findings, core.Finding{
		Severity: core.SeverityHigh, VulnSlug: "mock-slug",
		Title: "T", Description: "D", LineNumbers: []int{1},
		Recommendation: "R", Confidence: core.ConfidenceHigh,
		ProducedByRunID: "prior",
	})
	require.NoError(t, e.dataRoot.WriteFileRecord(rec))

	out, err := Revalidate(context.Background(), RevalidateOptions{
		ProjectID:    e.projectID,
		ProjectRoot:  e.projectRoot,
		DataRoot:     e.dataRoot,
		Backend:      NewMockBackend(),
		ProviderName: "anthropic",
	})
	require.NoError(t, err)
	require.Equal(t, 1, out.Revalidated)
	require.Equal(t, 1, out.TruePositives)
	require.Equal(t, core.VerdictTruePositive, e.readBack(t, "src/a.ts").Findings[0].Revalidation.Verdict)
}

func TestRevalidateSkipsAlreadyRevalidatedUnlessForced(t *testing.T) {
	e := newEnv(t)
	rec := e.seedRecord(t, "src/a.ts", core.StatusAnalyzed, "mock-slug")
	rec.Findings = append(rec.Findings, core.Finding{
		Severity: core.SeverityHigh, VulnSlug: "mock-slug",
		Title: "T", Description: "D", LineNumbers: []int{1},
		Recommendation: "R", Confidence: core.ConfidenceHigh,
		Revalidation: &core.Revalidation{
			Verdict: core.VerdictFalsePositive, Reasoning: "prior",
			RevalidatedAt: "2026-01-01", RunID: "prior", Model: "prior",
		},
	})
	require.NoError(t, e.dataRoot.WriteFileRecord(rec))

	out, err := Revalidate(context.Background(), RevalidateOptions{
		ProjectID:    e.projectID,
		ProjectRoot:  e.projectRoot,
		DataRoot:     e.dataRoot,
		Backend:      NewMockBackend(),
		ProviderName: "anthropic",
	})
	require.NoError(t, err)
	require.Equal(t, 0, out.Revalidated)

	// With force, the mock overrides FP to TP.
	out, err = Revalidate(context.Background(), RevalidateOptions{
		ProjectID:    e.projectID,
		ProjectRoot:  e.projectRoot,
		DataRoot:     e.dataRoot,
		Backend:      NewMockBackend(),
		ProviderName: "anthropic",
		Force:        true,
	})
	require.NoError(t, err)
	require.Equal(t, 1, out.Revalidated)
	require.Equal(t, core.VerdictTruePositive, e.readBack(t, "src/a.ts").Findings[0].Revalidation.Verdict)
}

func TestTriageAssignsPriority(t *testing.T) {
	e := newEnv(t)
	rec := e.seedRecord(t, "src/a.ts", core.StatusAnalyzed, "mock-slug")
	rec.Findings = append(rec.Findings, core.Finding{
		Severity: core.SeverityHigh, VulnSlug: "mock-slug",
		Title: "T", Description: "D", LineNumbers: []int{1},
		Recommendation: "R", Confidence: core.ConfidenceHigh,
	})
	require.NoError(t, e.dataRoot.WriteFileRecord(rec))

	out, err := Triage(context.Background(), TriageOptions{
		ProjectID:    e.projectID,
		ProjectRoot:  e.projectRoot,
		DataRoot:     e.dataRoot,
		Backend:      NewMockBackend(),
		ProviderName: "anthropic",
	})
	require.NoError(t, err)
	require.Equal(t, 1, out.Triaged)
	tri := e.readBack(t, "src/a.ts").Findings[0].Triage
	require.NotNil(t, tri)
	require.Equal(t, core.PriorityP1, tri.Priority)
	require.Equal(t, core.ExploitModerate, tri.Exploitability)
	require.Equal(t, core.ImpactHigh, tri.Impact)
}

func TestFindingDedupeBySlugAndTitle(t *testing.T) {
	e := newEnv(t)
	e.seedRecord(t, "src/a.ts", core.StatusPending, "mock-slug")

	// Pin the mock's title across both invocations.
	m := NewMockBackend()
	_, err := Process(context.Background(), baseOpts(e, m))
	require.NoError(t, err)
	require.Len(t, e.readBack(t, "src/a.ts").Findings, 1)

	// Reset to pending and reprocess; same (slug,title) should dedup.
	rec := e.readBack(t, "src/a.ts")
	rec.Status = core.StatusPending
	require.NoError(t, e.dataRoot.WriteFileRecord(rec))
	_, err = Process(context.Background(), baseOpts(e, NewMockBackend()))
	require.NoError(t, err)
	require.Len(t, e.readBack(t, "src/a.ts").Findings, 1, "duplicate finding was not deduped")
}
