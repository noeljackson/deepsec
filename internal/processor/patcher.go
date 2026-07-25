package processor

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/noeljackson/deepsec/internal/core"
	promptdata "github.com/noeljackson/deepsec/internal/processor/prompts"
)

type SourcePatchJSONBackend interface {
	ProposePatchJSON(ctx context.Context, system, user string, schema json.RawMessage) (string, core.Usage, float64, error)
}

type PatchFinding struct {
	ID          string                `json:"id"`
	ProjectID   string                `json:"project_id"`
	ProjectRoot string                `json:"-"`
	FilePath    string                `json:"file_path"`
	Index       int                   `json:"index"`
	FileContent string                `json:"file_content,omitempty"`
	Finding     core.Finding          `json:"finding"`
	Candidates  []core.CandidateMatch `json:"candidates,omitempty"`
}

type SourcePatch struct {
	Decision     string   `json:"decision"`
	Diff         string   `json:"diff,omitempty"`
	Rationale    string   `json:"rationale,omitempty"`
	Confidence   string   `json:"confidence,omitempty"`
	FilesTouched []string `json:"files_touched,omitempty"`
	Reason       string   `json:"reason,omitempty"`
}

type SourcePatchProposal struct {
	Patch SourcePatch
	Usage core.Usage
	Cost  float64
}

var SourcePatchSchema = mustJSON(map[string]any{
	"type":                 "object",
	"additionalProperties": false,
	"required":             []string{"decision", "confidence", "files_touched"},
	"properties": map[string]any{
		"decision":      map[string]any{"type": "string", "enum": []string{"patch", "cannot-fix", "out-of-scope"}},
		"diff":          map[string]any{"type": "string"},
		"rationale":     map[string]any{"type": "string"},
		"confidence":    map[string]any{"type": "string", "enum": []string{"high", "medium", "low"}},
		"files_touched": map[string]any{"type": "array", "items": map[string]any{"type": "string"}},
		"reason":        map[string]any{"type": "string"},
	},
})

func FindingID(projectID, filePath string, index int, f core.Finding) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\x00%s\x00%d\x00%s\x00%s\x00%s\x00%v", projectID, filePath, index, f.ProducedByRunID, f.VulnSlug, f.Title, f.LineNumbers)
	return hex.EncodeToString(h.Sum(nil))[:16]
}

func ProposeSourcePatch(ctx context.Context, backend AgentBackend, finding PatchFinding, withTools bool, maxCostUSD float64) (SourcePatchProposal, error) {
	if backend == nil {
		return SourcePatchProposal{}, errors.New("patcher requires a backend")
	}
	system, user, err := buildSourcePatchPrompt(finding)
	if err != nil {
		return SourcePatchProposal{}, err
	}
	if !withTools {
		raw, ok := backend.(SourcePatchJSONBackend)
		if !ok {
			return SourcePatchProposal{}, errors.New("backend does not support strict patch JSON")
		}
		body, usage, cost, err := raw.ProposePatchJSON(ctx, system, user, SourcePatchSchema)
		if err != nil {
			return SourcePatchProposal{}, err
		}
		p, err := ParseSourcePatch(body)
		if err != nil {
			return SourcePatchProposal{}, err
		}
		return SourcePatchProposal{Patch: p, Usage: usage, Cost: cost}, nil
	}
	out, err := backend.Investigate(ctx, &InvestigateBatch{
		ProjectRoot: finding.ProjectRoot,
		Files: []InvestigateFile{{
			Path:       finding.FilePath,
			Content:    finding.FileContent,
			Candidates: finding.Candidates,
		}},
		ProjectInfo:  "source patch proposal",
		PromptAppend: system + "\n\n" + user,
		ToolsEnabled: true,
		MaxTurns:     8,
		MaxCostUSD:   maxCostUSD,
		SlugNotes:    []string{finding.Finding.VulnSlug},
	})
	if err != nil {
		return SourcePatchProposal{}, err
	}
	if out.Refusal != nil {
		return SourcePatchProposal{}, fmt.Errorf("patcher refusal: %s", out.Refusal.Reason)
	}
	for _, r := range out.Results {
		for _, f := range r.Findings {
			if f.Description != "" {
				p, err := ParseSourcePatch(f.Description)
				if err != nil {
					return SourcePatchProposal{}, err
				}
				return SourcePatchProposal{Patch: p, Usage: out.Usage, Cost: out.CostUSD}, nil
			}
		}
	}
	return SourcePatchProposal{}, errors.New("patcher returned no patch JSON")
}

func ParseSourcePatch(body string) (SourcePatch, error) {
	if extracted := ExtractJSON(body); extracted != "" {
		body = extracted
	}
	var p SourcePatch
	if err := decodeStrict(body, &p); err != nil {
		return SourcePatch{}, fmt.Errorf("source patch schema: %w", err)
	}
	if err := p.Validate(); err != nil {
		return SourcePatch{}, err
	}
	return p, nil
}

func (p *SourcePatch) Validate() error {
	p.Decision = strings.TrimSpace(p.Decision)
	p.Diff = strings.TrimSpace(p.Diff)
	p.Rationale = strings.TrimSpace(p.Rationale)
	p.Confidence = strings.TrimSpace(p.Confidence)
	p.Reason = strings.TrimSpace(p.Reason)
	p.FilesTouched = normalizePatchFiles(p.FilesTouched)
	switch p.Confidence {
	case "high", "medium", "low":
	default:
		return fmt.Errorf("unsupported patch confidence %q", p.Confidence)
	}
	switch p.Decision {
	case "patch":
		if p.Diff == "" {
			return errors.New("patch decision requires diff")
		}
		if p.Rationale == "" {
			return errors.New("patch decision requires rationale")
		}
	case "cannot-fix", "out-of-scope":
		if p.Reason == "" {
			return fmt.Errorf("%s requires reason", p.Decision)
		}
	default:
		return fmt.Errorf("unsupported source patch decision %q", p.Decision)
	}
	if p.Diff != "" {
		files, err := DiffFilesTouched(p.Diff)
		if err != nil {
			return err
		}
		if !sameStringSet(files, p.FilesTouched) {
			return fmt.Errorf("files_touched %v does not match diff files %v", p.FilesTouched, files)
		}
	} else if len(p.FilesTouched) > 0 {
		return errors.New("files_touched requires diff")
	}
	return nil
}

func buildSourcePatchPrompt(finding PatchFinding) (string, string, error) {
	payload := struct {
		ID          string                `json:"id"`
		ProjectID   string                `json:"project_id"`
		FilePath    string                `json:"file_path"`
		Index       int                   `json:"index"`
		FileContent string                `json:"file_content"`
		Finding     core.Finding          `json:"finding"`
		Candidates  []core.CandidateMatch `json:"candidates,omitempty"`
	}{
		ID: finding.ID, ProjectID: finding.ProjectID, FilePath: finding.FilePath,
		Index: finding.Index, FileContent: core.RedactSecrets(finding.FileContent), Finding: core.RedactFinding(finding.Finding),
		Candidates: redactCandidates(finding.Candidates),
	}
	body, err := json.MarshalIndent(payload, "", "  ")
	if err != nil {
		return "", "", err
	}
	return promptdata.PatcherPrompt(), string(body), nil
}

func redactCandidates(candidates []core.CandidateMatch) []core.CandidateMatch {
	out := make([]core.CandidateMatch, len(candidates))
	for i, candidate := range candidates {
		out[i] = core.RedactCandidate(candidate)
	}
	return out
}

func BuildPatchFindings(projectID, projectRoot string, records []*core.FileRecord, sinceRun string, severities, slugs []string) ([]PatchFinding, error) {
	sevSet := stringSet(severities)
	slugSet := stringSet(slugs)
	out := []PatchFinding{}
	for _, rec := range records {
		body, _ := os.ReadFile(filepath.Join(projectRoot, filepath.FromSlash(rec.FilePath)))
		for i, f := range rec.Findings {
			if sinceRun != "" && f.ProducedByRunID != sinceRun {
				continue
			}
			if len(sevSet) > 0 && !sevSet[string(f.Severity)] {
				continue
			}
			if len(slugSet) > 0 && !slugSet[f.VulnSlug] {
				continue
			}
			out = append(out, PatchFinding{
				ID:          FindingID(projectID, rec.FilePath, i, f),
				ProjectID:   projectID,
				ProjectRoot: projectRoot,
				FilePath:    rec.FilePath,
				Index:       i,
				FileContent: string(body),
				Finding:     f,
				Candidates:  rec.Candidates,
			})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].FilePath != out[j].FilePath {
			return out[i].FilePath < out[j].FilePath
		}
		return out[i].Index < out[j].Index
	})
	return out, nil
}

func DiffFilesTouched(diff string) ([]string, error) {
	set := map[string]bool{}
	for _, line := range strings.Split(diff, "\n") {
		if strings.HasPrefix(line, "diff --git ") {
			parts := strings.Fields(line)
			if len(parts) >= 4 {
				addDiffPath(set, strings.TrimPrefix(parts[3], "b/"))
			}
			continue
		}
		if strings.HasPrefix(line, "+++ ") {
			p := strings.TrimSpace(strings.TrimPrefix(line, "+++ "))
			if p != "/dev/null" {
				addDiffPath(set, strings.TrimPrefix(p, "b/"))
			}
		}
	}
	out := sortedSet(set)
	if len(out) == 0 {
		return nil, errors.New("diff touches no files")
	}
	for _, p := range out {
		if err := core.AssertSafeFilePath(p); err != nil {
			return nil, err
		}
	}
	return out, nil
}

func addDiffPath(set map[string]bool, p string) {
	p = strings.TrimSpace(p)
	p = strings.TrimPrefix(p, "a/")
	p = strings.TrimPrefix(p, "b/")
	if p == "" || p == "/dev/null" {
		return
	}
	set[filepath.ToSlash(filepath.Clean(filepath.FromSlash(p)))] = true
}

func normalizePatchFiles(files []string) []string {
	set := map[string]bool{}
	for _, f := range files {
		addDiffPath(set, f)
	}
	return sortedSet(set)
}

func stringSet(xs []string) map[string]bool {
	out := map[string]bool{}
	for _, x := range xs {
		x = strings.TrimSpace(x)
		if x != "" {
			out[x] = true
		}
	}
	return out
}

func sortedSet(set map[string]bool) []string {
	out := make([]string, 0, len(set))
	for k := range set {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func sameStringSet(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}
