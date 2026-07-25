package commands

import (
	"encoding/json"
	"fmt"
	"strings"

	"github.com/noeljackson/deepsec/internal/cli"
	"github.com/noeljackson/deepsec/internal/core"
	"github.com/spf13/cobra"
)

// NewExportCmd is a filtered JSON dump of findings.
func NewExportCmd(loader func() (*cli.Context, error)) *cobra.Command {
	var projectID, minSeverity, runID, verdict, slug, prefix, output, format string
	cmd := &cobra.Command{
		Use:   "export",
		Short: "Filtered JSON export of findings",
		RunE: func(cmd *cobra.Command, _ []string) error {
			ctx, err := loader()
			if err != nil {
				return err
			}
			records, err := ctx.DataRoot.LoadAllFileRecords(projectID)
			if err != nil {
				return err
			}
			minSev := core.SeverityLow
			if minSeverity != "" {
				minSev = core.Severity(strings.ToUpper(minSeverity))
				if minSev.Rank() == 0 {
					return fmt.Errorf("unknown severity: %s", minSeverity)
				}
			}
			var wantVerdict *core.RevalidationVerdict
			if verdict != "" {
				v := core.RevalidationVerdict(strings.ToLower(verdict))
				wantVerdict = &v
			}

			out := make([]exportRow, 0)
			for _, rec := range records {
				if prefix != "" && !strings.HasPrefix(rec.FilePath, prefix) {
					continue
				}
				for i := range rec.Findings {
					f := &rec.Findings[i]
					if f.Severity.Rank() < minSev.Rank() {
						continue
					}
					if runID != "" && f.ProducedByRunID != runID {
						continue
					}
					if slug != "" && f.VulnSlug != slug {
						continue
					}
					if wantVerdict != nil {
						if f.Revalidation == nil || f.Revalidation.Verdict != *wantVerdict {
							continue
						}
					}
					out = append(out, exportRow{FilePath: rec.FilePath, Finding: f, GitInfo: rec.GitInfo})
				}
			}
			switch strings.ToLower(format) {
			case "", "json":
				body, err := json.MarshalIndent(out, "", "  ")
				if err != nil {
					return err
				}
				return write(output, body)
			case "sarif":
				body, err := renderSARIF(out, projectID)
				if err != nil {
					return err
				}
				return write(output, body)
			}
			return fmt.Errorf("unknown format %q (try 'json' or 'sarif')", format)
		},
	}
	cmd.Flags().StringVar(&projectID, "project-id", "", "Project id (required)")
	_ = cmd.MarkFlagRequired("project-id")
	cmd.Flags().StringVar(&minSeverity, "min-severity", "", "Minimum severity")
	cmd.Flags().StringVar(&runID, "run-id", "", "Only findings produced by this run")
	cmd.Flags().StringVar(&verdict, "verdict", "", "true-positive / false-positive / fixed / uncertain / accepted-risk")
	cmd.Flags().StringVar(&slug, "slug", "", "Only this vulnSlug")
	cmd.Flags().StringVar(&prefix, "prefix", "", "File-path prefix filter")
	cmd.Flags().StringVar(&output, "output", "", "Write to this path (default: stdout)")
	cmd.Flags().StringVar(&format, "format", "json", "json | sarif")
	return cmd
}

func write(path string, body []byte) error {
	if path == "" {
		fmt.Println(string(body))
		return nil
	}
	return writePrivateFile(path, body)
}

// exportRow is the on-wire shape for JSON export. SARIF emission
// reuses the same rows.
type exportRow struct {
	FilePath string        `json:"filePath"`
	Finding  *core.Finding `json:"finding"`
	GitInfo  *core.GitInfo `json:"gitInfo,omitempty"`
}

// renderSARIF produces a minimal SARIF 2.1.0 document. Covers the
// fields GitHub Code Scanning consumes; deeper SARIF features (taxa,
// related locations, etc.) can be added if needed.
func renderSARIF(rows []exportRow, projectID string) ([]byte, error) {
	results := make([]map[string]any, 0, len(rows))
	rules := map[string]map[string]any{}

	for _, r := range rows {
		ruleID := r.Finding.VulnSlug
		if _, ok := rules[ruleID]; !ok {
			rules[ruleID] = map[string]any{
				"id":   ruleID,
				"name": ruleID,
				"shortDescription": map[string]any{
					"text": r.Finding.Title,
				},
				"helpUri": "https://github.com/noeljackson/deepsec",
			}
		}
		startLine := 1
		if len(r.Finding.LineNumbers) > 0 {
			startLine = r.Finding.LineNumbers[0]
		}
		results = append(results, map[string]any{
			"ruleId":  ruleID,
			"level":   sarifLevel(r.Finding.Severity),
			"message": map[string]any{"text": r.Finding.Description},
			"locations": []map[string]any{{
				"physicalLocation": map[string]any{
					"artifactLocation": map[string]any{"uri": r.FilePath},
					"region":           map[string]any{"startLine": startLine},
				},
			}},
		})
	}

	ruleList := make([]map[string]any, 0, len(rules))
	for _, v := range rules {
		ruleList = append(ruleList, v)
	}

	doc := map[string]any{
		"$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/master/Schemata/sarif-schema-2.1.0.json",
		"version": "2.1.0",
		"runs": []map[string]any{{
			"tool": map[string]any{
				"driver": map[string]any{
					"name":    "deepsec",
					"rules":   ruleList,
					"version": "0.1.0",
				},
			},
			"results": results,
		}},
	}
	return json.MarshalIndent(doc, "", "  ")
}

func sarifLevel(s core.Severity) string {
	switch s {
	case core.SeverityCritical, core.SeverityHigh, core.SeverityHighBug:
		return "error"
	case core.SeverityMedium, core.SeverityBug:
		return "warning"
	}
	return "note"
}
