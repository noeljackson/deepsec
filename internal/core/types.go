// Package core holds the data model, paths, and persistence layer for
// deepsec. Field names match the TypeScript implementation exactly so
// data/<projectId>/ directories written by either are interchangeable.
package core

import (
	"encoding/json"
)

// Severity ranks findings highest-to-lowest by security impact.
type Severity string

const (
	SeverityCritical Severity = "CRITICAL"
	SeverityHigh     Severity = "HIGH"
	SeverityHighBug  Severity = "HIGH_BUG"
	SeverityMedium   Severity = "MEDIUM"
	SeverityBug      Severity = "BUG"
	SeverityLow      Severity = "LOW"
)

// Rank returns the security-impact ranking (higher = worse). Used for
// sorting and BTreeMap-like ordering — do NOT rely on Severity string
// comparison, which sorts alphabetically.
func (s Severity) Rank() int {
	switch s {
	case SeverityCritical:
		return 6
	case SeverityHigh:
		return 5
	case SeverityHighBug:
		return 4
	case SeverityMedium:
		return 3
	case SeverityBug:
		return 2
	case SeverityLow:
		return 1
	}
	return 0
}

// Confidence captures how sure the AI is about a finding.
type Confidence string

const (
	ConfidenceHigh   Confidence = "high"
	ConfidenceMedium Confidence = "medium"
	ConfidenceLow    Confidence = "low"
)

// RevalidationVerdict is the revalidator's verdict on an existing finding.
type RevalidationVerdict string

const (
	VerdictTruePositive  RevalidationVerdict = "true-positive"
	VerdictFalsePositive RevalidationVerdict = "false-positive"
	VerdictFixed         RevalidationVerdict = "fixed"
	VerdictUncertain     RevalidationVerdict = "uncertain"
	VerdictAcceptedRisk  RevalidationVerdict = "accepted-risk"
)

// TriagePriority bucket from the `triage` stage.
type TriagePriority string

const (
	PriorityP0   TriagePriority = "P0"
	PriorityP1   TriagePriority = "P1"
	PriorityP2   TriagePriority = "P2"
	PrioritySkip TriagePriority = "skip"
)

type Exploitability string

const (
	ExploitTrivial   Exploitability = "trivial"
	ExploitModerate  Exploitability = "moderate"
	ExploitDifficult Exploitability = "difficult"
)

type Impact string

const (
	ImpactCritical Impact = "critical"
	ImpactHigh     Impact = "high"
	ImpactMedium   Impact = "medium"
	ImpactLow      Impact = "low"
)

// FileStatus tracks where a FileRecord is in the pipeline.
type FileStatus string

const (
	StatusPending    FileStatus = "pending"
	StatusProcessing FileStatus = "processing"
	StatusAnalyzed   FileStatus = "analyzed"
	StatusError      FileStatus = "error"
)

// AnalysisPhase distinguishes process vs revalidate entries in history.
type AnalysisPhase string

const (
	PhaseProcess    AnalysisPhase = "process"
	PhaseRevalidate AnalysisPhase = "revalidate"
)

// CandidateMatch is a single scanner hit from a regex or AST matcher.
type CandidateMatch struct {
	VulnSlug       string `json:"vulnSlug"`
	LineNumbers    []int  `json:"lineNumbers"`
	Snippet        string `json:"snippet"`
	MatchedPattern string `json:"matchedPattern"`
}

// Usage records token-level cost reported by the AI backend.
type Usage struct {
	InputTokens              uint64 `json:"inputTokens"`
	OutputTokens             uint64 `json:"outputTokens"`
	CacheReadInputTokens     uint64 `json:"cacheReadInputTokens"`
	CacheCreationInputTokens uint64 `json:"cacheCreationInputTokens"`
}

// RefusalSkipped describes a single file the model declined to look at.
type RefusalSkipped struct {
	FilePath string `json:"filePath,omitempty"`
	Reason   string `json:"reason"`
}

// RefusalReport is populated when the AI agent declined to investigate.
type RefusalReport struct {
	Refused bool             `json:"refused"`
	Reason  string           `json:"reason,omitempty"`
	Skipped []RefusalSkipped `json:"skipped,omitempty"`
	Raw     string           `json:"raw,omitempty"`
}

// AnalysisEntry is appended to a FileRecord each time the AI agent looks
// at the file. Append-only: history grows; nothing is overwritten.
type AnalysisEntry struct {
	RunID             string         `json:"runId"`
	InvestigatedAt    string         `json:"investigatedAt"`
	DurationMs        uint64         `json:"durationMs"`
	DurationAPIMs     *uint64        `json:"durationApiMs,omitempty"`
	AgentType         string         `json:"agentType"`
	Model             string         `json:"model"`
	ModelConfig       map[string]any `json:"modelConfig"`
	AgentSessionID    string         `json:"agentSessionId,omitempty"`
	FindingCount      int            `json:"findingCount"`
	NumTurns          *int           `json:"numTurns,omitempty"`
	Phase             AnalysisPhase  `json:"phase,omitempty"`
	CostUSD           *float64       `json:"costUsd,omitempty"`
	Usage             *Usage         `json:"usage,omitempty"`
	Refusal           *RefusalReport `json:"refusal,omitempty"`
	CodexStderr       string         `json:"codexStderr,omitempty"`
	ReinvestigateMark *int           `json:"reinvestigateMarker,omitempty"`
}

// Revalidation is the verdict the revalidate stage attaches to a finding.
type Revalidation struct {
	Verdict          RevalidationVerdict `json:"verdict"`
	Reasoning        string              `json:"reasoning"`
	AdjustedSeverity *Severity           `json:"adjustedSeverity,omitempty"`
	RevalidatedAt    string              `json:"revalidatedAt"`
	RunID            string              `json:"runId"`
	Model            string              `json:"model"`
}

// Triage is the priority/exploitability/impact bucket from `triage`.
type Triage struct {
	Priority       TriagePriority `json:"priority"`
	Exploitability Exploitability `json:"exploitability"`
	Impact         Impact         `json:"impact"`
	Reasoning      string         `json:"reasoning"`
	TriagedAt      string         `json:"triagedAt"`
	Model          string         `json:"model"`
}

// Finding is a single AI-produced vulnerability report.
type Finding struct {
	Severity        Severity      `json:"severity"`
	VulnSlug        string        `json:"vulnSlug"`
	Title           string        `json:"title"`
	Description     string        `json:"description"`
	LineNumbers     []int         `json:"lineNumbers"`
	Recommendation  string        `json:"recommendation"`
	Confidence      Confidence    `json:"confidence"`
	Triage          *Triage       `json:"triage,omitempty"`
	Revalidation    *Revalidation `json:"revalidation,omitempty"`
	ProducedByRunID string        `json:"producedByRunId,omitempty"`
}

// OwnershipContributor — one row of the ownership oracle's contributors[].
type OwnershipContributor struct {
	Email          string  `json:"email"`
	Name           string  `json:"name"`
	GithubUsername string  `json:"github_username"`
	Score          float64 `json:"score"`
	Context        string  `json:"context"`
	LastContrib    string  `json:"last_contrib"`
}

type OwnershipManager struct {
	Email       string `json:"email"`
	SlackUserID string `json:"slack_user_id"`
}

type OwnershipOncall struct {
	Name           string `json:"name"`
	Email          string `json:"email"`
	SlackUserID    string `json:"slack_user_id"`
	GithubUsername string `json:"github_username"`
}

type OwnershipEscalationTeam struct {
	Name             string           `json:"name"`
	Slug             string           `json:"slug"`
	Source           string           `json:"source"`
	EscalationPathID string           `json:"escalation_path_id"`
	SlackChannelID   *string          `json:"slack_channel_id"`
	Manager          OwnershipManager `json:"manager"`
	CurrentOncall    OwnershipOncall  `json:"current_oncall"`
}

type OwnershipApprover struct {
	Owner     string  `json:"owner"`
	OwnerType string  `json:"owner_type"`
	Pattern   *string `json:"pattern"`
	IsPrimary bool    `json:"is_primary"`
	IsDirect  bool    `json:"is_direct"`
}

type OwnershipData struct {
	Contributors    []OwnershipContributor    `json:"contributors"`
	EscalationTeams []OwnershipEscalationTeam `json:"escalationTeams"`
	Approvers       []OwnershipApprover       `json:"approvers"`
	FetchedAt       string                    `json:"fetchedAt"`
}

type GitCommitter struct {
	Name  string `json:"name"`
	Email string `json:"email"`
	Date  string `json:"date"`
}

type GitInfo struct {
	RecentCommitters []GitCommitter `json:"recentCommitters"`
	EnrichedAt       string         `json:"enrichedAt"`
	Ownership        *OwnershipData `json:"ownership,omitempty"`
}

// FileRecord is the core per-file accumulator. Source of truth for
// everything deepsec knows about one file.
type FileRecord struct {
	FilePath  string `json:"filePath"`
	ProjectID string `json:"projectId"`

	Candidates          []CandidateMatch `json:"candidates"`
	LastScannedAt       string           `json:"lastScannedAt"`
	LastScannedRunID    string           `json:"lastScannedRunId"`
	FileHash            string           `json:"fileHash"`
	LastMatcherPackHash string           `json:"lastMatcherPackHash,omitempty"`

	Findings        []Finding       `json:"findings"`
	AnalysisHistory []AnalysisEntry `json:"analysisHistory"`

	GitInfo *GitInfo `json:"gitInfo,omitempty"`

	Status        FileStatus `json:"status"`
	LockedByRunID string     `json:"lockedByRunId,omitempty"`
	LockedAt      string     `json:"lockedAt,omitempty"`
}

// ProjectConfig is the per-project metadata stored as `project.json`.
type ProjectConfig struct {
	ProjectID string `json:"projectId"`
	RootPath  string `json:"rootPath"`
	CreatedAt string `json:"createdAt"`
	GithubURL string `json:"githubUrl,omitempty"`
}

// EnsureUTF8 returns a marshal-safe copy of v. Used in tests + writers
// that need to confirm the wire shape round-trips.
func EnsureUTF8(v any) ([]byte, error) {
	return json.MarshalIndent(v, "", "  ")
}
