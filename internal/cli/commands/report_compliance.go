package commands

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"runtime/debug"
	"sort"
	"time"

	"github.com/noeljackson/deepsec/internal/core"
	"github.com/noeljackson/deepsec/internal/processor/prompts"
	"github.com/noeljackson/deepsec/internal/scanner"
)

// ComplianceReport is the structured-audit format emitted by
// `deepsec report --format soc2|ssdf`. The shape is versioned via
// SchemaVersion so future iterations don't break existing audit
// pipelines. The optional Signature block lets a downstream verifier
// confirm the report hasn't been tampered with since generation.
type ComplianceReport struct {
	SchemaVersion string              `json:"schema_version"`
	Format        string              `json:"format"`
	GeneratedAt   string              `json:"generated_at"`
	ProjectID     string              `json:"project_id"`
	Manifest      ComplianceManifest  `json:"manifest"`
	Findings      []ComplianceFinding `json:"findings"`
	Signature     *ComplianceSig      `json:"signature,omitempty"`
}

// ComplianceManifest captures the provenance an auditor cares about:
// what binary, what matcher pack, what prompts, what models, what
// cost. Each finding inherits this context.
type ComplianceManifest struct {
	ScannerVersion  string   `json:"scanner_version"`
	BuildDate       string   `json:"build_date,omitempty"`
	MatcherPackHash string   `json:"matcher_pack_hash"`
	PromptPackHash  string   `json:"prompt_pack_hash"`
	Providers       []string `json:"providers"`
	Models          []string `json:"models"`
	TotalCostUSD    float64  `json:"total_cost_usd"`
	TotalRunCount   int      `json:"total_run_count"`
	FindingsCount   int      `json:"findings_count"`
}

// ComplianceFinding is one row in the audit-formatted report. Field
// names follow common audit-tooling conventions; the schema is
// designed to round-trip through GRC ingestion without manual
// remapping.
type ComplianceFinding struct {
	FindingID       string `json:"finding_id"`
	DetectedAt      string `json:"detected_at"`
	DetectedByRun   string `json:"detected_by_run"`
	Provider        string `json:"provider"`
	Model           string `json:"model"`
	Severity        string `json:"severity"`
	CWE             string `json:"cwe,omitempty"`
	VulnSlug        string `json:"vuln_slug"`
	File            string `json:"file"`
	Lines           []int  `json:"lines"`
	Title           string `json:"title"`
	Description     string `json:"description"`
	Recommendation  string `json:"recommendation"`
	Confidence      string `json:"confidence"`
	Status          string `json:"status"`
	StatusChangedAt string `json:"status_changed_at,omitempty"`
	StatusReason    string `json:"status_reason,omitempty"`
	EvidenceHash    string `json:"evidence_hash"`
}

// ComplianceSig is an HMAC-SHA256 over the canonical-JSON encoding of
// the report with Signature elided. The verifier recomputes and
// compares against Value. KeyHint is the first 16 hex chars of
// SHA-256(key), so multiple keys can be rotated and the verifier can
// pick the right one.
type ComplianceSig struct {
	Algorithm string `json:"algorithm"`
	KeyHint   string `json:"key_hint"`
	Value     string `json:"value"`
}

// BuildComplianceReport assembles a compliance-formatted report for a
// project. The format string is recorded verbatim for downstream
// tools that distinguish SOC2 from SSDF, but the schema is identical
// — both formats carry the same evidence; what differs is which
// fields downstream tooling consumes.
func BuildComplianceReport(format, projectID string, records []*core.FileRecord, runs []core.RunMeta) (*ComplianceReport, error) {
	matchersHash, err := hashEmbedFS(scanner.BundledMatcherFS())
	if err != nil {
		return nil, fmt.Errorf("hashing matcher pack: %w", err)
	}
	promptsHash, err := hashEmbedFS(prompts.BundledPromptFS())
	if err != nil {
		return nil, fmt.Errorf("hashing prompt pack: %w", err)
	}

	providers, models := providerInventory(records)
	totalCost := 0.0
	for _, r := range runs {
		if r.Stats.TotalCostUSD != nil {
			totalCost += *r.Stats.TotalCostUSD
		}
	}

	findings := make([]ComplianceFinding, 0)
	for _, rec := range records {
		for i := range rec.Findings {
			findings = append(findings, complianceFindingFor(rec, &rec.Findings[i]))
		}
	}
	sort.Slice(findings, func(i, j int) bool { return findings[i].FindingID < findings[j].FindingID })

	rep := &ComplianceReport{
		SchemaVersion: "1.0",
		Format:        format,
		GeneratedAt:   core.NowISO(),
		ProjectID:     projectID,
		Manifest: ComplianceManifest{
			ScannerVersion:  scannerVersion(),
			BuildDate:       buildDate(),
			MatcherPackHash: matchersHash,
			PromptPackHash:  promptsHash,
			Providers:       providers,
			Models:          models,
			TotalCostUSD:    totalCost,
			TotalRunCount:   len(runs),
			FindingsCount:   len(findings),
		},
		Findings: findings,
	}
	return rep, nil
}

// SignComplianceReport computes the HMAC-SHA256 of the report (with
// Signature nil) and stores it on the report.
func SignComplianceReport(rep *ComplianceReport, key []byte) error {
	if len(key) == 0 {
		return errors.New("compliance: empty signing key")
	}
	rep.Signature = nil
	body, err := json.Marshal(rep)
	if err != nil {
		return err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(body)
	digest := mac.Sum(nil)

	keyDigest := sha256.Sum256(key)
	rep.Signature = &ComplianceSig{
		Algorithm: "HMAC-SHA256",
		KeyHint:   hex.EncodeToString(keyDigest[:8]),
		Value:     hex.EncodeToString(digest),
	}
	return nil
}

// VerifyComplianceReport recomputes the HMAC over the report (with
// Signature elided) and compares against the stored Value.
func VerifyComplianceReport(rep *ComplianceReport, key []byte) error {
	if rep.Signature == nil {
		return errors.New("compliance: report has no signature")
	}
	if rep.Signature.Algorithm != "HMAC-SHA256" {
		return fmt.Errorf("compliance: unsupported signature algorithm %q", rep.Signature.Algorithm)
	}
	want, err := hex.DecodeString(rep.Signature.Value)
	if err != nil {
		return fmt.Errorf("compliance: signature decode: %w", err)
	}
	stash := rep.Signature
	rep.Signature = nil
	body, err := json.Marshal(rep)
	rep.Signature = stash
	if err != nil {
		return err
	}
	mac := hmac.New(sha256.New, key)
	mac.Write(body)
	if !hmac.Equal(mac.Sum(nil), want) {
		return errors.New("compliance: signature mismatch")
	}
	return nil
}

func complianceFindingFor(rec *core.FileRecord, f *core.Finding) ComplianceFinding {
	provider, model := lastInvestigationProviderAndModel(rec, f.ProducedByRunID)
	cf := ComplianceFinding{
		FindingID:      stableFindingID(rec.FilePath, f),
		DetectedAt:     producedAt(rec, f.ProducedByRunID),
		DetectedByRun:  f.ProducedByRunID,
		Provider:       provider,
		Model:          model,
		Severity:       string(f.Severity),
		VulnSlug:       f.VulnSlug,
		File:           rec.FilePath,
		Lines:          append([]int(nil), f.LineNumbers...),
		Title:          f.Title,
		Description:    f.Description,
		Recommendation: f.Recommendation,
		Confidence:     string(f.Confidence),
		Status:         complianceStatus(f),
		EvidenceHash:   evidenceHash(rec.FilePath, f, rec.FileHash),
	}
	if f.Revalidation != nil {
		cf.StatusChangedAt = f.Revalidation.RevalidatedAt
		cf.StatusReason = f.Revalidation.Reasoning
	}
	return cf
}

// stableFindingID is a deterministic identifier for a finding: the
// SHA-256 of (file, slug, line numbers) truncated to 16 hex chars.
// Survives re-scans; same code + same matcher + same lines → same id.
func stableFindingID(file string, f *core.Finding) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\n%s\n", file, f.VulnSlug)
	for _, n := range f.LineNumbers {
		fmt.Fprintf(h, "%d\n", n)
	}
	sum := h.Sum(nil)
	return hex.EncodeToString(sum[:8])
}

// evidenceHash binds the finding to the file hash at scan time. An
// auditor checks: if a later scan of the same file produces the same
// FileHash, the evidence still corresponds to the same source.
func evidenceHash(file string, f *core.Finding, fileHash string) string {
	h := sha256.New()
	fmt.Fprintf(h, "%s\n%s\n%s\n%s\n", file, fileHash, f.VulnSlug, f.ProducedByRunID)
	for _, n := range f.LineNumbers {
		fmt.Fprintf(h, "%d\n", n)
	}
	return hex.EncodeToString(h.Sum(nil))
}

func complianceStatus(f *core.Finding) string {
	if f.Revalidation == nil {
		return "open"
	}
	switch f.Revalidation.Verdict {
	case core.VerdictTruePositive:
		return "open"
	case core.VerdictFalsePositive:
		return "false-positive"
	case core.VerdictFixed:
		return "verified-fix"
	case core.VerdictUncertain:
		return "uncertain"
	}
	if f.Revalidation.Verdict != "" {
		return string(f.Revalidation.Verdict)
	}
	return "open"
}

func producedAt(rec *core.FileRecord, runID string) string {
	for i := len(rec.AnalysisHistory) - 1; i >= 0; i-- {
		if rec.AnalysisHistory[i].RunID == runID {
			return rec.AnalysisHistory[i].InvestigatedAt
		}
	}
	return rec.LastScannedAt
}

func lastInvestigationProviderAndModel(rec *core.FileRecord, runID string) (string, string) {
	for i := len(rec.AnalysisHistory) - 1; i >= 0; i-- {
		if rec.AnalysisHistory[i].RunID == runID {
			return rec.AnalysisHistory[i].AgentType, rec.AnalysisHistory[i].Model
		}
	}
	if n := len(rec.AnalysisHistory); n > 0 {
		return rec.AnalysisHistory[n-1].AgentType, rec.AnalysisHistory[n-1].Model
	}
	return "", ""
}

func providerInventory(records []*core.FileRecord) ([]string, []string) {
	providerSet := map[string]struct{}{}
	modelSet := map[string]struct{}{}
	for _, rec := range records {
		for _, a := range rec.AnalysisHistory {
			if a.AgentType != "" {
				providerSet[a.AgentType] = struct{}{}
			}
			if a.Model != "" {
				modelSet[a.Model] = struct{}{}
			}
		}
	}
	providers := keysSorted(providerSet)
	models := keysSorted(modelSet)
	return providers, models
}

func keysSorted(m map[string]struct{}) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

// hashEmbedFS returns SHA-256 over a canonical-ordered concatenation
// of every file in the embedded FS. Deterministic per build.
func hashEmbedFS(fsys fs.FS) (string, error) {
	var paths []string
	if err := fs.WalkDir(fsys, ".", func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() {
			paths = append(paths, p)
		}
		return nil
	}); err != nil {
		return "", err
	}
	sort.Strings(paths)
	h := sha256.New()
	for _, p := range paths {
		body, err := fs.ReadFile(fsys, p)
		if err != nil {
			return "", err
		}
		fmt.Fprintf(h, "%s\n", p)
		h.Write(body)
		h.Write([]byte{0})
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// scannerVersion reports the deepsec build version using go's build
// info — falls back to "(devel)" for local builds.
func scannerVersion() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return "(unknown)"
	}
	for _, s := range bi.Settings {
		if s.Key == "vcs.revision" && s.Value != "" {
			return s.Value
		}
	}
	if bi.Main.Version != "" {
		return bi.Main.Version
	}
	return "(devel)"
}

func buildDate() string {
	bi, ok := debug.ReadBuildInfo()
	if !ok {
		return ""
	}
	for _, s := range bi.Settings {
		if s.Key == "vcs.time" {
			return s.Value
		}
	}
	return ""
}

// writeComplianceReport serialises and writes the report; signs first
// if DEEPSEC_REPORT_SIGNING_KEY is set in the environment.
func writeComplianceReport(rep *ComplianceReport, path string) error {
	if key := os.Getenv("DEEPSEC_REPORT_SIGNING_KEY"); key != "" {
		if err := SignComplianceReport(rep, []byte(key)); err != nil {
			return err
		}
	}
	body, err := json.MarshalIndent(rep, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(path), 0o755); err != nil {
		return err
	}
	return os.WriteFile(path, body, 0o600)
}

// verifyComplianceFile reads, parses, and verifies a compliance
// report from disk. Used by `deepsec report --verify <path>`.
func verifyComplianceFile(path string, key []byte) error {
	body, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	var rep ComplianceReport
	if err := json.Unmarshal(body, &rep); err != nil {
		return fmt.Errorf("parse report: %w", err)
	}
	if err := VerifyComplianceReport(&rep, key); err != nil {
		return err
	}
	// Belt-and-suspenders: also confirm the embedded matcher/prompt
	// hashes still match what this binary would compute. A mismatch
	// is not an integrity failure but is worth flagging — the report
	// was generated by a different binary build.
	mh, _ := hashEmbedFS(scanner.BundledMatcherFS())
	ph, _ := hashEmbedFS(prompts.BundledPromptFS())
	if mh != rep.Manifest.MatcherPackHash {
		_, _ = fmt.Fprintf(os.Stderr, "warning: matcher pack hash differs from current binary (report=%s, current=%s)\n", rep.Manifest.MatcherPackHash, mh)
	}
	if ph != rep.Manifest.PromptPackHash {
		_, _ = fmt.Fprintf(os.Stderr, "warning: prompt pack hash differs from current binary (report=%s, current=%s)\n", rep.Manifest.PromptPackHash, ph)
	}
	_ = time.Now
	return nil
}
