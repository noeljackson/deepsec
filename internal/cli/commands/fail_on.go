package commands

import (
	"fmt"
	"strings"

	"github.com/noeljackson/deepsec/internal/cli"
	"github.com/noeljackson/deepsec/internal/core"
)

// enforceFailOn inspects findings produced by `runID` and returns a
// non-nil error when any finding's severity meets or exceeds the
// configured threshold. Used by --fail-on on `process` (and by
// extension `report`) so CI can short-circuit on bad PRs.
//
// Findings whose revalidation marks them as false-positive or fixed
// are ignored — a real-only gate that matches the behaviour CI users
// will expect ("don't fail my PR for a verdict-cleared finding").
func enforceFailOn(ctx *cli.Context, projectID, runID, threshold string) error {
	threshold = strings.ToUpper(strings.TrimSpace(threshold))
	if threshold == "" {
		return nil
	}
	minSev := core.Severity(threshold)
	if minSev.Rank() == 0 {
		return fmt.Errorf("--fail-on: unknown severity %q (want CRITICAL|HIGH|MEDIUM|LOW)", threshold)
	}
	records, err := ctx.DataRoot.LoadAllFileRecords(projectID)
	if err != nil {
		return err
	}
	var matched int
	for _, rec := range records {
		for i := range rec.Findings {
			f := &rec.Findings[i]
			if runID != "" && f.ProducedByRunID != runID {
				continue
			}
			if f.Severity.Rank() < minSev.Rank() {
				continue
			}
			if f.Revalidation != nil {
				v := f.Revalidation.Verdict
				if v == core.VerdictFalsePositive || v == core.VerdictFixed {
					continue
				}
			}
			matched++
		}
	}
	if matched > 0 {
		return fmt.Errorf("fail-on: %d findings at or above %s", matched, minSev)
	}
	return nil
}
