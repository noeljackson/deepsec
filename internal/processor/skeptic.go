package processor

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"

	"github.com/noeljackson/deepsec/internal/core"
)

// applySkeptic runs the adversarial second pass on every finding in
// `out`, mutating the result in place. Returns the additional cost
// incurred and the first non-fatal error encountered (for telemetry —
// the caller decides what to do with it).
//
// Survival policy:
//   - true-positive: keep the finding; apply AdjustedSeverity if set
//   - false-positive: drop the finding
//   - fixed: drop the finding (the skeptic believes mitigation is present)
//   - uncertain: keep but demote severity to LOW
//
// On any non-survival decision the finding's Recommendation is
// prefixed with a marker so downstream consumers can tell the skeptic
// touched it.
func applySkeptic(ctx context.Context, opts ProcessOptions, out *InvestigateOutput) (float64, error) {
	if out == nil || opts.Backend == nil {
		return 0, nil
	}
	var totalCost float64
	var firstErr error
	for ri := range out.Results {
		r := &out.Results[ri]
		if len(r.Findings) == 0 {
			continue
		}
		content, err := readFileForSkeptic(opts.ProjectRoot, r.FilePath)
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		inputs := make([]RevalidateInputFinding, 0, len(r.Findings))
		for i, f := range r.Findings {
			inputs = append(inputs, RevalidateInputFinding{
				Index:       i,
				Severity:    f.Severity,
				VulnSlug:    f.VulnSlug,
				Title:       f.Title,
				Description: f.Description,
				LineNumbers: f.LineNumbers,
			})
		}
		verdicts, _, _, err := opts.Backend.Revalidate(ctx, &RevalidateInput{
			ProjectRoot: opts.ProjectRoot,
			FilePath:    r.FilePath,
			FileContent: content,
			Findings:    inputs,
			Skeptic:     true,
		})
		if err != nil {
			if firstErr == nil {
				firstErr = err
			}
			continue
		}
		r.Findings = applySkepticVerdicts(r.Findings, verdicts)
	}
	return totalCost, firstErr
}

func applySkepticVerdicts(findings []ProducedFinding, verdicts []RevalidatedFinding) []ProducedFinding {
	if len(verdicts) == 0 {
		return findings
	}
	byIndex := map[int]RevalidatedFinding{}
	for _, v := range verdicts {
		byIndex[v.Index] = v
	}
	kept := findings[:0]
	for i, f := range findings {
		v, ok := byIndex[i]
		if !ok {
			// No verdict for this index — be conservative, keep the
			// original finding rather than dropping it silently.
			kept = append(kept, f)
			continue
		}
		switch v.Verdict {
		case core.VerdictTruePositive:
			if v.AdjustedSeverity != nil {
				f.Severity = *v.AdjustedSeverity
			}
			f.Description = annotateSkeptic(f.Description, "survived skeptic", v.Reasoning)
			kept = append(kept, f)
		case core.VerdictFalsePositive, core.VerdictFixed:
			// dropped
		case core.VerdictUncertain:
			f.Severity = core.SeverityLow
			f.Description = annotateSkeptic(f.Description, "demoted by skeptic (uncertain)", v.Reasoning)
			kept = append(kept, f)
		default:
			kept = append(kept, f)
		}
	}
	return kept
}

func annotateSkeptic(description, tag, reason string) string {
	if reason == "" {
		return description
	}
	return description + "\n\n[" + tag + "] " + reason
}

func readFileForSkeptic(projectRoot, filePath string) (string, error) {
	if projectRoot == "" {
		return "", errors.New("skeptic requires a project root")
	}
	if err := core.AssertSafeFilePath(filePath); err != nil {
		return "", fmt.Errorf("skeptic: %w", err)
	}
	body, err := os.ReadFile(filepath.Join(projectRoot, filePath))
	if err != nil {
		return "", err
	}
	return string(body), nil
}
