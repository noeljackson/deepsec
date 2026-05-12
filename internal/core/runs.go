package core

import (
	"encoding/json"
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
)

type RunType string

const (
	RunTypeScan       RunType = "scan"
	RunTypeProcess    RunType = "process"
	RunTypeRevalidate RunType = "revalidate"
)

type RunPhase string

const (
	RunPhaseRunning RunPhase = "running"
	RunPhaseDone    RunPhase = "done"
	RunPhaseError   RunPhase = "error"
)

type ScannerMode string

const (
	ScannerModeFull  ScannerMode = "full"
	ScannerModeFiles ScannerMode = "files"
)

type InvocationMode string

const (
	InvocationModeScan   InvocationMode = "scan"
	InvocationModeDirect InvocationMode = "direct"
)

type ScannerConfig struct {
	MatcherSlugs []string    `json:"matcherSlugs"`
	Mode         ScannerMode `json:"mode,omitempty"`
	Source       string      `json:"source,omitempty"`
	FileCount    *int        `json:"fileCount,omitempty"`
}

type ProcessorConfig struct {
	AgentType      string         `json:"agentType"`
	Model          string         `json:"model"`
	ModelConfig    map[string]any `json:"modelConfig"`
	InvocationMode InvocationMode `json:"invocationMode,omitempty"`
	Source         string         `json:"source,omitempty"`
}

type RunStats struct {
	FilesScanned        *int     `json:"filesScanned,omitempty"`
	CandidatesFound     *int     `json:"candidatesFound,omitempty"`
	FilesProcessed      *int     `json:"filesProcessed,omitempty"`
	FindingsCount       *int     `json:"findingsCount,omitempty"`
	TotalCostUSD        *float64 `json:"totalCostUsd,omitempty"`
	TotalInputTokens    *uint64  `json:"totalInputTokens,omitempty"`
	TotalOutputTokens   *uint64  `json:"totalOutputTokens,omitempty"`
	TotalDurationMs     *uint64  `json:"totalDurationMs,omitempty"`
	FindingsRevalidated *int     `json:"findingsRevalidated,omitempty"`
	TruePositives       *int     `json:"truePositives,omitempty"`
	FalsePositives      *int     `json:"falsePositives,omitempty"`
	Fixed               *int     `json:"fixed,omitempty"`
	Uncertain           *int     `json:"uncertain,omitempty"`
}

type RunMeta struct {
	RunID           string           `json:"runId"`
	ProjectID       string           `json:"projectId"`
	RootPath        string           `json:"rootPath"`
	CreatedAt       string           `json:"createdAt"`
	CompletedAt     string           `json:"completedAt,omitempty"`
	Type            RunType          `json:"type"`
	Phase           RunPhase         `json:"phase"`
	ScannerConfig   *ScannerConfig   `json:"scannerConfig,omitempty"`
	ProcessorConfig *ProcessorConfig `json:"processorConfig,omitempty"`
	Stats           RunStats         `json:"stats"`
}

func NewRunMeta(projectID, runID, rootPath string, t RunType) *RunMeta {
	return &RunMeta{
		RunID:     runID,
		ProjectID: projectID,
		RootPath:  rootPath,
		CreatedAt: NowISO(),
		Type:      t,
		Phase:     RunPhaseRunning,
	}
}

func (r DataRoot) WriteRunMeta(m *RunMeta) error {
	p, err := r.RunMetaPath(m.ProjectID, m.RunID)
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
		return err
	}
	body, err := json.MarshalIndent(m, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(p, body, 0o644)
}

func (r DataRoot) ReadRunMeta(projectID, runID string) (*RunMeta, error) {
	p, err := r.RunMetaPath(projectID, runID)
	if err != nil {
		return nil, err
	}
	body, err := os.ReadFile(p)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	var m RunMeta
	if err := json.Unmarshal(body, &m); err != nil {
		return nil, err
	}
	return &m, nil
}

// CompleteRun reads, mutates phase + completedAt, writes back. Returns
// the updated meta. Returns (nil, nil) when the run is missing.
func (r DataRoot) CompleteRun(projectID, runID string, phase RunPhase) (*RunMeta, error) {
	m, err := r.ReadRunMeta(projectID, runID)
	if err != nil || m == nil {
		return nil, err
	}
	m.Phase = phase
	m.CompletedAt = NowISO()
	if err := r.WriteRunMeta(m); err != nil {
		return nil, err
	}
	return m, nil
}

// ListRuns returns all runs for a project, newest first by run_id.
// Sorts on `RunID` because that field embeds a sortable timestamp + nonce
// and is stable across runs sharing a wall-clock millisecond.
func (r DataRoot) ListRuns(projectID string) ([]*RunMeta, error) {
	d, err := r.RunsDir(projectID)
	if err != nil {
		return nil, err
	}
	entries, err := os.ReadDir(d)
	if err != nil {
		if errors.Is(err, fs.ErrNotExist) {
			return nil, nil
		}
		return nil, err
	}
	out := make([]*RunMeta, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		body, err := os.ReadFile(filepath.Join(d, e.Name()))
		if err != nil {
			continue
		}
		var m RunMeta
		if err := json.Unmarshal(body, &m); err != nil {
			continue
		}
		out = append(out, &m)
	}
	sort.Slice(out, func(i, j int) bool { return out[i].RunID > out[j].RunID })
	return out, nil
}
