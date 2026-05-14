package commands

import (
	"bytes"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/noeljackson/deepsec/internal/core"
)

func TestResolveSinceAccepts(t *testing.T) {
	cases := []string{"", "all", "30d", "24h", "7d", "2026-04-01"}
	for _, c := range cases {
		if _, _, err := resolveSince(c); err != nil {
			t.Fatalf("resolveSince(%q) unexpected error: %v", c, err)
		}
	}
}

func TestResolveSinceRejectsGarbage(t *testing.T) {
	if _, _, err := resolveSince("zorp"); err == nil {
		t.Fatalf("expected error on garbage --since")
	}
}

func TestParseSpendBy(t *testing.T) {
	for _, in := range []string{"agent", "phase", "slug", "file", "AGENT", ""} {
		if _, err := parseSpendBy(in); err != nil {
			t.Fatalf("parseSpendBy(%q) error: %v", in, err)
		}
	}
	if _, err := parseSpendBy("country"); err == nil {
		t.Fatalf("expected error for invalid dimension")
	}
}

func TestSpendAggAbsorbAttributesCorrectly(t *testing.T) {
	cost := func(f float64) *float64 { return &f }
	rec := &core.FileRecord{
		FilePath: "src/a.ts",
		Findings: []core.Finding{
			{VulnSlug: "ssrf", ProducedByRunID: "run-1"},
			{VulnSlug: "open-redirect", ProducedByRunID: "run-1"},
		},
		AnalysisHistory: []core.AnalysisEntry{
			{
				RunID:          "run-1",
				InvestigatedAt: time.Now().UTC().Format(time.RFC3339),
				AgentType:      "anthropic",
				Phase:          core.PhaseProcess,
				CostUSD:        cost(2.00),
			},
			{
				RunID:          "run-2",
				InvestigatedAt: time.Now().UTC().Format(time.RFC3339),
				AgentType:      "zai-coding",
				Phase:          "skeptic",
				CostUSD:        cost(0.50),
			},
		},
	}
	a := newSpendAgg()
	a.absorb(rec, time.Time{})
	if got := a.totalUSD; got != 2.50 {
		t.Fatalf("total: want 2.50, got %v", got)
	}
	if a.byAgent["anthropic"] != 2.00 || a.byAgent["zai-coding"] != 0.50 {
		t.Fatalf("byAgent: %v", a.byAgent)
	}
	if a.byPhase["process"] != 2.00 || a.byPhase["skeptic"] != 0.50 {
		t.Fatalf("byPhase: %v", a.byPhase)
	}
	if a.byFile["src/a.ts"] != 2.50 {
		t.Fatalf("byFile: %v", a.byFile)
	}
	// $2.00 split across 2 slugs = $1.00 each; run-2 has no findings → "(no findings)"
	if a.bySlug["ssrf"] != 1.00 || a.bySlug["open-redirect"] != 1.00 {
		t.Fatalf("bySlug split wrong: %v", a.bySlug)
	}
	if a.bySlug["(no findings)"] != 0.50 {
		t.Fatalf("bySlug missing no-finding bucket: %v", a.bySlug)
	}
}

func TestSpendAggHonoursCutoff(t *testing.T) {
	cost := func(f float64) *float64 { return &f }
	rec := &core.FileRecord{
		FilePath: "src/a.ts",
		AnalysisHistory: []core.AnalysisEntry{
			{
				InvestigatedAt: "2025-01-01T00:00:00Z",
				AgentType:      "anthropic",
				CostUSD:        cost(10.00),
			},
			{
				InvestigatedAt: time.Now().UTC().Format(time.RFC3339),
				AgentType:      "anthropic",
				CostUSD:        cost(1.00),
			},
		},
	}
	a := newSpendAgg()
	a.absorb(rec, time.Now().UTC().Add(-24*time.Hour))
	if a.totalUSD != 1.00 {
		t.Fatalf("cutoff did not exclude old entry: total=%v", a.totalUSD)
	}
}

func TestWriteSpendJSONShape(t *testing.T) {
	a := newSpendAgg()
	a.totalUSD = 3.50
	a.byAgent["anthropic"] = 3.00
	a.byAgent["openai"] = 0.50
	a.runs["r-1"] = true
	a.entries = 2

	var buf bytes.Buffer
	if err := writeSpend(&buf, a, spendByAgent, spendFormatJSON, "all time"); err != nil {
		t.Fatalf("writeSpend: %v", err)
	}
	var got map[string]any
	if err := json.Unmarshal(buf.Bytes(), &got); err != nil {
		t.Fatalf("output not JSON: %v\n%s", err, buf.String())
	}
	if got["dimension"] != "agent" {
		t.Fatalf("dimension wrong: %v", got["dimension"])
	}
	if got["total"].(float64) != 3.50 {
		t.Fatalf("total wrong: %v", got["total"])
	}
	rows, _ := got["rows"].([]any)
	if len(rows) != 2 {
		t.Fatalf("rows: want 2, got %d", len(rows))
	}
	first := rows[0].(map[string]any)
	if first["key"] != "anthropic" {
		t.Fatalf("rows not sorted by cost desc: first=%v", first)
	}
}

func TestWriteSpendCSV(t *testing.T) {
	a := newSpendAgg()
	a.totalUSD = 1.00
	a.byPhase["process"] = 1.00
	var buf bytes.Buffer
	if err := writeSpend(&buf, a, spendByPhase, spendFormatCSV, "all time"); err != nil {
		t.Fatalf("writeSpend csv: %v", err)
	}
	s := buf.String()
	if !strings.HasPrefix(s, "key,usd,pct\n") {
		t.Fatalf("csv header missing: %q", s)
	}
	if !strings.Contains(s, "process,1.0000,100.00") {
		t.Fatalf("csv row missing: %q", s)
	}
}

func TestParseDayDuration(t *testing.T) {
	if d, err := parseDayDuration("30d"); err != nil || d != 30*24*time.Hour {
		t.Fatalf("30d: %v %v", d, err)
	}
	if _, err := parseDayDuration("30h"); err == nil {
		t.Fatalf("expected error for non-day")
	}
}
