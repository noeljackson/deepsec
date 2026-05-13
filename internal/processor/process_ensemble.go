package processor

import (
	"context"
	"fmt"
	"sort"
	"strconv"
	"strings"

	"github.com/noeljackson/deepsec/internal/core"
)

// NamedBackend pairs a provider profile name with its configured
// AgentBackend, used by EnsembleProcess to attribute findings.
type NamedBackend struct {
	Name    string
	Backend AgentBackend
}

// EnsembleOutcome aggregates per-agent runs plus the cross-agent
// agreement summary computed after all agents complete.
type EnsembleOutcome struct {
	Outcomes     []*ProcessOutcome
	RunIDs       []string
	AgentByRunID map[string]string
	// Findings counts post-merge.
	UniqueFindings int
	ConsensusCount int // findings with >=2 agreeing agents
	SoloCount      int // findings produced by exactly one agent
}

// EnsembleProcess runs Process once per agent (serially) and then
// merges findings across runs by stable identity. Findings flagged by
// multiple agents have their `AgreeingAgents` field populated. Costs
// roughly N× a single-agent invocation — opt-in via `--agents csv`.
//
// Implementation choice — serial vs parallel: serial keeps quota and
// budget tracking semantics straightforward, avoids head-of-line
// blocking when one provider hits rate-limit, and is simpler to test.
// The throughput cost is irrelevant for PR-check workflows where the
// file set is small.
func EnsembleProcess(ctx context.Context, opts ProcessOptions, agents []NamedBackend) (*EnsembleOutcome, error) {
	if len(agents) == 0 {
		return nil, fmt.Errorf("ensemble: at least one agent required")
	}
	if len(agents) == 1 {
		opts.Backend = agents[0].Backend
		opts.ProviderName = agents[0].Name
		single, err := Process(ctx, opts)
		if err != nil {
			return nil, err
		}
		return &EnsembleOutcome{
			Outcomes:     []*ProcessOutcome{single},
			RunIDs:       []string{single.RunID},
			AgentByRunID: map[string]string{single.RunID: agents[0].Name},
		}, nil
	}
	out := &EnsembleOutcome{
		AgentByRunID: map[string]string{},
	}
	for i, ab := range agents {
		// Reset every analyzed file back to pending before the next
		// agent's run, so each agent re-investigates the same set.
		// The first agent's run consumes the originally-pending set.
		if i > 0 {
			if err := resetPendingForReinvestigation(opts.DataRoot, opts.ProjectID); err != nil {
				return nil, fmt.Errorf("ensemble: reset before %s: %w", ab.Name, err)
			}
		}
		opts.Backend = ab.Backend
		opts.ProviderName = ab.Name
		oc, err := Process(ctx, opts)
		if err != nil {
			return nil, fmt.Errorf("ensemble: %s: %w", ab.Name, err)
		}
		// Process returns nil for "every batch failed but the loop
		// completed" — the failure shows up as ErrorBatchCount > 0
		// and AnalysisCount == 0 in the outcome and as phase=error in
		// the on-disk RunMeta. Treat that as a fatal ensemble failure
		// so we don't silently roll a broken agent's zero findings
		// into the merge (#74).
		if oc.ErrorBatchCount > 0 && oc.AnalysisCount == 0 {
			return nil, fmt.Errorf("ensemble: %s produced 0 findings across %d failed batches — check provider auth, model availability, and rate limits",
				ab.Name, oc.ErrorBatchCount)
		}
		out.Outcomes = append(out.Outcomes, oc)
		out.RunIDs = append(out.RunIDs, oc.RunID)
		out.AgentByRunID[oc.RunID] = ab.Name
	}
	if err := mergeEnsembleAgreement(opts.DataRoot, opts.ProjectID, out); err != nil {
		return nil, err
	}
	return out, nil
}

// resetPendingForReinvestigation flips analyzed file records back to
// pending so the next agent's Process call picks them up.
func resetPendingForReinvestigation(root core.DataRoot, projectID string) error {
	records, err := root.LoadAllFileRecords(projectID)
	if err != nil {
		return err
	}
	for _, rec := range records {
		if rec == nil {
			continue
		}
		if rec.Status == core.StatusAnalyzed {
			rec.Status = core.StatusPending
			rec.LockedByRunID = ""
			rec.LockedAt = ""
			if err := root.WriteFileRecord(rec); err != nil {
				return err
			}
		}
	}
	return nil
}

// mergeEnsembleAgreement walks every file record and groups its
// findings by stable identity (vulnSlug + sorted lines + normalized
// title). The first finding in each group is kept; AgreeingAgents
// captures every agent (by name) whose run produced a finding with
// that identity. Later duplicates from other agents are removed.
func mergeEnsembleAgreement(root core.DataRoot, projectID string, out *EnsembleOutcome) error {
	records, err := root.LoadAllFileRecords(projectID)
	if err != nil {
		return err
	}
	for _, rec := range records {
		if rec == nil {
			continue
		}
		// Only consider findings produced by this ensemble's runs.
		eligible := make([]int, 0, len(rec.Findings))
		for i := range rec.Findings {
			if _, ok := out.AgentByRunID[rec.Findings[i].ProducedByRunID]; ok {
				eligible = append(eligible, i)
			}
		}
		if len(eligible) == 0 {
			continue
		}
		// Group by identity. The first index in each group is the canonical.
		groups := map[string][]int{}
		order := []string{}
		for _, idx := range eligible {
			key := findingIdentity(&rec.Findings[idx])
			if _, ok := groups[key]; !ok {
				order = append(order, key)
			}
			groups[key] = append(groups[key], idx)
		}
		toDrop := map[int]bool{}
		for _, key := range order {
			group := groups[key]
			canonical := group[0]
			agentSet := map[string]struct{}{}
			for _, idx := range group {
				agent := out.AgentByRunID[rec.Findings[idx].ProducedByRunID]
				if agent != "" {
					agentSet[agent] = struct{}{}
				}
			}
			agents := make([]string, 0, len(agentSet))
			for a := range agentSet {
				agents = append(agents, a)
			}
			sort.Strings(agents)
			rec.Findings[canonical].AgreeingAgents = agents
			out.UniqueFindings++
			if len(agents) >= 2 {
				out.ConsensusCount++
			} else {
				out.SoloCount++
			}
			for _, dup := range group[1:] {
				toDrop[dup] = true
			}
		}
		if len(toDrop) > 0 {
			kept := rec.Findings[:0]
			for i, f := range rec.Findings {
				if toDrop[i] {
					continue
				}
				kept = append(kept, f)
			}
			rec.Findings = kept
		}
		if err := root.WriteFileRecord(rec); err != nil {
			return err
		}
	}
	return nil
}

// findingIdentity is the stable key used to consider two findings
// equivalent across ensemble agents. Title is folded for whitespace
// and case so cosmetic phrasing differences don't break agreement.
func findingIdentity(f *core.Finding) string {
	lines := append([]int(nil), f.LineNumbers...)
	sort.Ints(lines)
	parts := make([]string, 0, len(lines))
	for _, n := range lines {
		parts = append(parts, strconv.Itoa(n))
	}
	title := strings.Join(strings.Fields(strings.ToLower(f.Title)), " ")
	return f.VulnSlug + "|" + strings.Join(parts, ",") + "|" + title
}
