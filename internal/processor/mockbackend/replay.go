package mockbackend

import (
	"bufio"
	"context"
	"encoding/json"
	"fmt"
	"os"
	"reflect"
	"sync"

	"github.com/noeljackson/deepsec/internal/core"
	"github.com/noeljackson/deepsec/internal/processor"
	"github.com/noeljackson/deepsec/internal/processor/providers"
)

type RecordedResponse struct {
	BatchPaths []string                    `json:"batchPaths"`
	Output     processor.InvestigateOutput `json:"output"`
}

type Backend struct {
	mu        sync.Mutex
	model     string
	kind      providers.Kind
	responses []RecordedResponse
	next      int
}

func New(path string) (*Backend, error) {
	responses, err := LoadResponses(path)
	if err != nil {
		return nil, err
	}
	return &Backend{
		model:     "mock-replay",
		kind:      providers.KindAnthropic,
		responses: responses,
	}, nil
}

func LoadResponses(path string) ([]RecordedResponse, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var responses []RecordedResponse
	sc := bufio.NewScanner(f)
	for line := 1; sc.Scan(); line++ {
		body := sc.Bytes()
		if len(body) == 0 {
			continue
		}
		var r RecordedResponse
		if err := json.Unmarshal(body, &r); err != nil {
			return nil, fmt.Errorf("%s:%d: malformed response JSONL: %w", path, line, err)
		}
		if len(r.BatchPaths) == 0 {
			return nil, fmt.Errorf("%s:%d: batchPaths is required", path, line)
		}
		responses = append(responses, r)
	}
	if err := sc.Err(); err != nil {
		return nil, err
	}
	return responses, nil
}

func (b *Backend) Kind() providers.Kind { return b.kind }
func (b *Backend) Model() string        { return b.model }

func (b *Backend) Investigate(ctx context.Context, batch *processor.InvestigateBatch) (*processor.InvestigateOutput, error) {
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
	out := entry.Output
	out.CostUSD = 0
	return &out, nil
}

func (b *Backend) Revalidate(ctx context.Context, in *processor.RevalidateInput) ([]processor.RevalidatedFinding, core.Usage, uint64, error) {
	return nil, core.Usage{}, 0, fmt.Errorf("mock replay backend does not implement revalidation")
}

func (b *Backend) Triage(ctx context.Context, in *processor.TriageInput) (*processor.TriagedFinding, core.Usage, uint64, error) {
	return nil, core.Usage{}, 0, fmt.Errorf("mock replay backend does not implement triage")
}

func (b *Backend) Consumed() int {
	b.mu.Lock()
	defer b.mu.Unlock()
	return b.next
}

func (b *Backend) TotalResponses() int { return len(b.responses) }
