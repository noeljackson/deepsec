package mockbackend

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"math/rand/v2"
	"os"
	"reflect"
	"sync"

	"github.com/noeljackson/deepsec/internal/core"
	"github.com/noeljackson/deepsec/internal/processor"
	"github.com/noeljackson/deepsec/internal/processor/providers"
)

type ReplayBackend interface {
	processor.AgentBackend
	Consumed() int
	TotalResponses() int
}

type StochasticAlternative struct {
	Weight float64                     `json:"weight"`
	Output processor.InvestigateOutput `json:"output"`
}

type StochasticResponse struct {
	BatchPaths   []string                `json:"batchPaths"`
	Alternatives []StochasticAlternative `json:"alternatives"`
}

type StochasticBackend struct {
	mu        sync.Mutex
	model     string
	kind      providers.Kind
	responses []StochasticResponse
	next      int
	rng       *rand.Rand
}

func NewSeeded(path string, seed uint64) (ReplayBackend, error) {
	mode, err := responseMode(path)
	if err != nil {
		return nil, err
	}
	if mode == "stochastic" {
		return NewStochastic(path, seed)
	}
	return New(path)
}

func NewStochastic(path string, seed uint64) (*StochasticBackend, error) {
	responses, err := LoadStochasticResponses(path)
	if err != nil {
		return nil, err
	}
	return &StochasticBackend{
		model:     "mock-stochastic",
		kind:      providers.KindAnthropic,
		responses: responses,
		rng:       rand.New(rand.NewPCG(seed, seed^0x9e3779b97f4a7c15)),
	}, nil
}

func LoadStochasticResponses(path string) ([]StochasticResponse, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var responses []StochasticResponse
	sc := bufio.NewScanner(f)
	for line := 1; sc.Scan(); line++ {
		body := sc.Bytes()
		if len(body) == 0 {
			continue
		}
		var r StochasticResponse
		if err := json.Unmarshal(body, &r); err != nil {
			return nil, fmt.Errorf("%s:%d: malformed stochastic response JSONL: %w", path, line, err)
		}
		if len(r.BatchPaths) == 0 {
			return nil, fmt.Errorf("%s:%d: batchPaths is required", path, line)
		}
		if len(r.Alternatives) == 0 {
			return nil, fmt.Errorf("%s:%d: alternatives is required", path, line)
		}
		for i, alt := range r.Alternatives {
			if alt.Weight <= 0 {
				return nil, fmt.Errorf("%s:%d: alternatives[%d].weight must be positive", path, line, i)
			}
		}
		responses = append(responses, r)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return responses, nil
}

func responseMode(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()

	sc := bufio.NewScanner(f)
	for line := 1; sc.Scan(); line++ {
		body := sc.Bytes()
		if len(body) == 0 {
			continue
		}
		var probe struct {
			Alternatives json.RawMessage `json:"alternatives"`
		}
		if err := json.Unmarshal(body, &probe); err != nil {
			return "", fmt.Errorf("%s:%d: malformed response JSONL: %w", path, line, err)
		}
		if len(probe.Alternatives) > 0 {
			return "stochastic", nil
		}
		return "replay", nil
	}
	if err := sc.Err(); err != nil {
		return "", err
	}
	return "replay", nil
}

func (b *StochasticBackend) Kind() providers.Kind { return b.kind }
func (b *StochasticBackend) Model() string        { return b.model }

func (b *StochasticBackend) Investigate(ctx context.Context, batch *processor.InvestigateBatch) (*processor.InvestigateOutput, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	got := make([]string, len(batch.Files))
	for i, f := range batch.Files {
		got[i] = f.Path
	}

	b.mu.Lock()
	defer b.mu.Unlock()
	if b.next >= len(b.responses) {
		return nil, fmt.Errorf("expected recorded batch at position %d, got %v: responses exhausted", b.next+1, got)
	}
	entry := b.responses[b.next]
	position := b.next + 1
	b.next++
	if !reflect.DeepEqual(entry.BatchPaths, got) {
		return nil, fmt.Errorf("expected batch %v at position %d, got %v", entry.BatchPaths, position, got)
	}
	out := b.pick(entry).Output
	out.CostUSD = 0
	return &out, nil
}

func (b *StochasticBackend) pick(entry StochasticResponse) StochasticAlternative {
	total := 0.0
	for _, alt := range entry.Alternatives {
		total += alt.Weight
	}
	draw := b.rng.Float64() * total
	for _, alt := range entry.Alternatives {
		draw -= alt.Weight
		if draw < 0 {
			return alt
		}
	}
	return entry.Alternatives[len(entry.Alternatives)-1]
}

func (b *StochasticBackend) Revalidate(ctx context.Context, in *processor.RevalidateInput) ([]processor.RevalidatedFinding, core.Usage, uint64, error) {
	return nil, core.Usage{}, 0, fmt.Errorf("mock stochastic backend does not implement revalidation")
}

func (b *StochasticBackend) Triage(ctx context.Context, in *processor.TriageInput) (*processor.TriagedFinding, core.Usage, uint64, error) {
	return nil, core.Usage{}, 0, fmt.Errorf("mock stochastic backend does not implement triage")
}

func (b *StochasticBackend) Consumed() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.next
}

func (b *StochasticBackend) TotalResponses() int { return len(b.responses) }
