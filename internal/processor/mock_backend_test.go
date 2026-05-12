package processor

import (
	"context"
	"fmt"
	"sync"
	"time"

	"github.com/noeljackson/deepsec/internal/core"
	"github.com/noeljackson/deepsec/internal/processor/providers"
)

// MockBackend is a deterministic AgentBackend used by the pipeline
// tests. Records every call and supports knobs for quota / refusal /
// latency to exercise the process loop's edge cases.
type MockBackend struct {
	model            string
	kind             providers.Kind
	mu               sync.Mutex
	investigateCalls int
	revalidateCalls  int
	triageCalls      int
	investigated     [][]string

	FindingsPerFile int
	ReturnRefusal   bool
	QuotaAfter      int // 0 = never; N = succeed N times then quota
	Delay           time.Duration
}

func NewMockBackend() *MockBackend {
	return &MockBackend{
		model:           "mock-model",
		kind:            providers.KindAnthropic,
		FindingsPerFile: 1,
	}
}

func (m *MockBackend) Kind() providers.Kind { return m.kind }
func (m *MockBackend) Model() string        { return m.model }

func (m *MockBackend) InvestigateCalls() int {
	m.mu.Lock()
	defer m.mu.Unlock()
	return m.investigateCalls
}

func (m *MockBackend) InvestigatedBatches() [][]string {
	m.mu.Lock()
	defer m.mu.Unlock()
	out := make([][]string, len(m.investigated))
	for i, b := range m.investigated {
		out[i] = append([]string(nil), b...)
	}
	return out
}

func (m *MockBackend) Investigate(ctx context.Context, batch *InvestigateBatch) (*InvestigateOutput, error) {
	m.mu.Lock()
	n := m.investigateCalls
	m.investigateCalls++
	paths := make([]string, len(batch.Files))
	for i, f := range batch.Files {
		paths[i] = f.Path
	}
	m.investigated = append(m.investigated, paths)
	m.mu.Unlock()

	if m.Delay > 0 {
		select {
		case <-time.After(m.Delay):
		case <-ctx.Done():
			return nil, ctx.Err()
		}
	}
	if m.QuotaAfter > 0 && n >= m.QuotaAfter {
		return nil, &QuotaExhaustedError{Provider: "mock", Detail: "test-quota"}
	}
	if m.ReturnRefusal {
		return &InvestigateOutput{
			Refusal:    &core.RefusalReport{Refused: true, Reason: "test refusal"},
			Usage:      core.Usage{InputTokens: 1, OutputTokens: 1},
			DurationMs: uint64(m.Delay.Milliseconds()),
		}, nil
	}

	results := make([]InvestigateResult, 0, len(batch.Files))
	for _, f := range batch.Files {
		findings := make([]ProducedFinding, 0, m.FindingsPerFile)
		for i := 0; i < m.FindingsPerFile; i++ {
			findings = append(findings, ProducedFinding{
				Severity:       core.SeverityHigh,
				VulnSlug:       "mock-slug",
				Title:          fmt.Sprintf("Mock finding %d for %s", i, f.Path),
				Description:    "mock description",
				LineNumbers:    []int{1},
				Recommendation: "mock fix",
				Confidence:     core.ConfidenceHigh,
			})
		}
		results = append(results, InvestigateResult{FilePath: f.Path, Findings: findings})
	}
	return &InvestigateOutput{
		Results:    results,
		Usage:      core.Usage{InputTokens: 100, OutputTokens: 50},
		DurationMs: uint64(m.Delay.Milliseconds()),
		NumTurns:   1,
		CostUSD:    0.01,
	}, nil
}

func (m *MockBackend) Revalidate(ctx context.Context, in *RevalidateInput) ([]RevalidatedFinding, core.Usage, uint64, error) {
	m.mu.Lock()
	m.revalidateCalls++
	m.mu.Unlock()
	out := make([]RevalidatedFinding, 0, len(in.Findings))
	for _, f := range in.Findings {
		out = append(out, RevalidatedFinding{
			Index:     f.Index,
			Verdict:   core.VerdictTruePositive,
			Reasoning: "still present in current code",
		})
	}
	return out, core.Usage{}, 1, nil
}

func (m *MockBackend) Triage(ctx context.Context, in *TriageInput) (*TriagedFinding, core.Usage, uint64, error) {
	m.mu.Lock()
	m.triageCalls++
	m.mu.Unlock()
	return &TriagedFinding{
		Priority:       core.PriorityP1,
		Exploitability: core.ExploitModerate,
		Impact:         core.ImpactHigh,
		Reasoning:      "mock triage",
	}, core.Usage{}, 1, nil
}
