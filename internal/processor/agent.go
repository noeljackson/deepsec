// Package processor drives the AI investigation pipeline. The
// AgentBackend interface abstracts over Anthropic and any
// OpenAI-compatible provider (OpenAI, GLM, Kimi, DeepSeek, OpenRouter,
// Azure, vLLM, …).
package processor

import (
	"context"

	"github.com/noeljackson/deepsec/internal/core"
	"github.com/noeljackson/deepsec/internal/processor/providers"
)

// InvestigateFile is one source file in an investigation batch.
type InvestigateFile struct {
	Path       string
	Content    string
	Candidates []core.CandidateMatch
}

// InvestigateBatch is what the agent gets per call. The processor
// groups files by directory and asks the agent to look at each group
// in one round-trip.
type InvestigateBatch struct {
	ProjectRoot  string
	Files        []InvestigateFile
	ProjectInfo  string
	PromptAppend string
	TechTags     []string
	SlugNotes    []string // slugs present in this batch (used to pick prompt hints)
	ToolsEnabled bool
	MaxTurns     int
	MaxCostUSD   float64
	// CorePromptOverride, when non-empty, replaces the bundled CorePrompt
	// for this batch. Used by the prompt-evolution harness (#86) to A/B
	// candidate prompts against the bundled baseline.
	CorePromptOverride string
}

// ProducedFinding is the model's output for one candidate site.
type ProducedFinding struct {
	Severity       core.Severity   `json:"severity"`
	VulnSlug       string          `json:"vulnSlug"`
	Title          string          `json:"title"`
	Description    string          `json:"description"`
	LineNumbers    []int           `json:"lineNumbers"`
	Recommendation string          `json:"recommendation"`
	Confidence     core.Confidence `json:"confidence"`
}

// InvestigateResult is the per-file output (a batch returns N of these).
type InvestigateResult struct {
	FilePath string
	Findings []ProducedFinding
}

// InvestigateOutput is the full result of one InvestigateBatch call.
type InvestigateOutput struct {
	Results    []InvestigateResult
	Usage      core.Usage
	DurationMs uint64
	NumTurns   int
	CostUSD    float64
	// Refusal is set when the model explicitly declined. Non-nil means
	// the batch produced no useful output; the caller records it.
	Refusal *core.RefusalReport
}

// RevalidateInputFinding is one finding presented for revalidation.
type RevalidateInputFinding struct {
	Index       int
	Severity    core.Severity
	VulnSlug    string
	Title       string
	Description string
	LineNumbers []int
}

// RevalidateInput is one file's set of findings being revalidated.
type RevalidateInput struct {
	ProjectRoot string
	FilePath    string
	FileContent string
	Findings    []RevalidateInputFinding
	// Skeptic flips the revalidation prompt from "is this still
	// present" to "try to disprove this finding." The output shape is
	// identical (RevalidatedFinding) but verdicts are produced with a
	// more adversarial stance. Used by Process when --skeptic is set.
	Skeptic bool
}

// RevalidatedFinding is the agent's verdict on one input finding.
type RevalidatedFinding struct {
	Index            int                      `json:"index"`
	Verdict          core.RevalidationVerdict `json:"verdict"`
	Reasoning        string                   `json:"reasoning"`
	AdjustedSeverity *core.Severity           `json:"adjustedSeverity,omitempty"`
}

// TriageInput is one finding being triaged.
type TriageInput struct {
	FilePath string
	Finding  RevalidateInputFinding
}

// TriagedFinding is the agent's priority/exploitability/impact verdict.
type TriagedFinding struct {
	Priority       core.TriagePriority `json:"priority"`
	Exploitability core.Exploitability `json:"exploitability"`
	Impact         core.Impact         `json:"impact"`
	Reasoning      string              `json:"reasoning"`
}

// AgentBackend is the contract every AI provider implementation
// satisfies. Three methods, one for each stage that talks to an LLM.
type AgentBackend interface {
	// Kind returns the underlying implementation kind (anthropic vs
	// openai-compatible). The provider name is held by the caller.
	Kind() providers.Kind
	// Model returns the model identifier the backend is configured for.
	Model() string

	Investigate(ctx context.Context, batch *InvestigateBatch) (*InvestigateOutput, error)
	Revalidate(ctx context.Context, in *RevalidateInput) ([]RevalidatedFinding, core.Usage, uint64, error)
	Triage(ctx context.Context, in *TriageInput) (*TriagedFinding, core.Usage, uint64, error)
}

// QuotaExhaustedError is returned by backends when the provider says
// we've hit our rate / cost limit. The process pipeline catches it,
// flips a shared cancel flag, and stops dispatching new batches.
type QuotaExhaustedError struct {
	Provider string
	Detail   string
}

func (e *QuotaExhaustedError) Error() string {
	return "quota exhausted on " + e.Provider + ": " + e.Detail
}

// IsQuotaErr unwraps to a QuotaExhaustedError if the chain contains one.
func IsQuotaErr(err error) bool {
	_, ok := err.(*QuotaExhaustedError)
	return ok
}

// RefusalError indicates the model returned a refusal envelope. The
// process pipeline records it on AnalysisEntry.refusal and marks the
// batch's files as status=error.
type RefusalError struct {
	Reason string
}

func (e *RefusalError) Error() string { return "refusal: " + e.Reason }
