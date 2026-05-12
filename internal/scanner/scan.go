package scanner

import (
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/noeljackson/deepsec/internal/core"
)

// Options bundles the parameters every scan call needs.
type Options struct {
	ProjectID      string
	Root           string
	DataRoot       core.DataRoot
	MatcherOnly    []string
	MatcherExclude []string
	// ExtraMatcherPaths is a list of TOML files (or directories of TOML files)
	// to load on top of the bundled matcher pack. User matchers registered
	// with a slug that already exists in the bundle override it.
	ExtraMatcherPaths []string
	GithubURL         string
}

// LanguageStat is one row of the per-language scan summary.
type LanguageStat struct {
	Language       string
	FilesScanned   int
	FilesWithMatch int
}

// Outcome is what `Scan` returns.
type Outcome struct {
	RunID           string
	FilesScanned    int
	CandidateCount  int
	Detected        DetectedTech
	ActiveMatchers  []string
	SkippedMatchers []string
	LanguageStats   []LanguageStat
}

// FilesOutcome is what `ScanFiles` returns (no per-language stats, since
// the file list is bounded by the caller).
type FilesOutcome struct {
	RunID           string
	FilesScanned    int
	CandidateCount  int
	Detected        DetectedTech
	ActiveMatchers  []string
	SkippedMatchers []string
}

// Scan walks every file under opts.Root and writes FileRecords with
// candidates merged in.
func Scan(opts Options) (*Outcome, error) {
	if _, err := opts.DataRoot.EnsureProject(opts.ProjectID, opts.Root, opts.GithubURL); err != nil {
		return nil, err
	}
	runID := core.GenerateRunID()
	meta := core.NewRunMeta(opts.ProjectID, runID, opts.Root, core.RunTypeScan)
	if err := opts.DataRoot.WriteRunMeta(meta); err != nil {
		return nil, err
	}

	tech := Detect(opts.Root)
	if err := WriteTechJSON(opts.DataRoot, opts.ProjectID, tech); err != nil {
		return nil, err
	}

	reg, err := loadRegistry(opts)
	if err != nil {
		return nil, err
	}
	active, skipped := splitGated(reg, tech, opts.Root)

	files, err := WalkProject(opts.Root)
	if err != nil {
		return nil, err
	}

	candidateCount := 0
	byLang := map[string]*LanguageStat{}
	for _, rel := range files {
		abs := filepath.Join(opts.Root, rel)
		body, err := os.ReadFile(abs)
		if err != nil {
			continue
		}
		content := strings.ReplaceAll(string(body), "\r\n", "\n")
		matches := runMatchers(reg, active, content, rel)
		lang := langFor(rel)
		st, ok := byLang[lang]
		if !ok {
			st = &LanguageStat{Language: lang}
			byLang[lang] = st
		}
		st.FilesScanned++
		if len(matches) > 0 {
			st.FilesWithMatch++
		}
		candidateCount += len(matches)
		if err := upsertRecord(opts.DataRoot, opts.ProjectID, rel, runID, content, matches); err != nil {
			return nil, err
		}
	}

	mode := core.ScannerModeFull
	meta.ScannerConfig = &core.ScannerConfig{
		MatcherSlugs: active,
		Mode:         mode,
	}
	fs := len(files)
	meta.Stats.FilesScanned = &fs
	meta.Stats.CandidatesFound = &candidateCount
	if err := opts.DataRoot.WriteRunMeta(meta); err != nil {
		return nil, err
	}
	if _, err := opts.DataRoot.CompleteRun(opts.ProjectID, runID, core.RunPhaseDone); err != nil {
		return nil, err
	}

	stats := make([]LanguageStat, 0, len(byLang))
	for _, s := range byLang {
		stats = append(stats, *s)
	}
	sort.Slice(stats, func(i, j int) bool { return stats[i].Language < stats[j].Language })

	return &Outcome{
		RunID:           runID,
		FilesScanned:    fs,
		CandidateCount:  candidateCount,
		Detected:        tech,
		ActiveMatchers:  active,
		SkippedMatchers: skipped,
		LanguageStats:   stats,
	}, nil
}

// ScanFiles scans only the given relative file paths. Writes a
// FileRecord for every listed path, even when no matchers fire.
func ScanFiles(opts Options, files []string, source string) (*FilesOutcome, error) {
	if _, err := opts.DataRoot.EnsureProject(opts.ProjectID, opts.Root, opts.GithubURL); err != nil {
		return nil, err
	}
	runID := core.GenerateRunID()
	meta := core.NewRunMeta(opts.ProjectID, runID, opts.Root, core.RunTypeScan)
	if err := opts.DataRoot.WriteRunMeta(meta); err != nil {
		return nil, err
	}

	tech := Detect(opts.Root)
	if err := WriteTechJSON(opts.DataRoot, opts.ProjectID, tech); err != nil {
		return nil, err
	}

	reg, err := loadRegistry(opts)
	if err != nil {
		return nil, err
	}
	active, skipped := splitGated(reg, tech, opts.Root)

	candidateCount := 0
	for _, rel := range files {
		abs := filepath.Join(opts.Root, rel)
		body, _ := os.ReadFile(abs)
		content := strings.ReplaceAll(string(body), "\r\n", "\n")
		matches := runMatchers(reg, active, content, rel)
		candidateCount += len(matches)
		if err := upsertRecord(opts.DataRoot, opts.ProjectID, rel, runID, content, matches); err != nil {
			return nil, err
		}
	}

	count := len(files)
	mode := core.ScannerModeFiles
	meta.ScannerConfig = &core.ScannerConfig{
		MatcherSlugs: active,
		Mode:         mode,
		Source:       source,
		FileCount:    &count,
	}
	meta.Stats.FilesScanned = &count
	meta.Stats.CandidatesFound = &candidateCount
	if err := opts.DataRoot.WriteRunMeta(meta); err != nil {
		return nil, err
	}
	if _, err := opts.DataRoot.CompleteRun(opts.ProjectID, runID, core.RunPhaseDone); err != nil {
		return nil, err
	}

	return &FilesOutcome{
		RunID:           runID,
		FilesScanned:    count,
		CandidateCount:  candidateCount,
		Detected:        tech,
		ActiveMatchers:  active,
		SkippedMatchers: skipped,
	}, nil
}

// loadRegistry builds the registry used by Scan / ScanFiles: bundled
// pack first, then any user-supplied paths from opts.ExtraMatcherPaths,
// then the only/exclude filter. Entries from extras override bundled
// entries that share a slug.
func loadRegistry(opts Options) (*Registry, error) {
	reg, err := WithBuiltin()
	if err != nil {
		return nil, err
	}
	for _, p := range opts.ExtraMatcherPaths {
		info, err := os.Stat(p)
		if err != nil {
			return nil, fmt.Errorf("matchers.extra_paths %q: %w", p, err)
		}
		if info.IsDir() {
			if err := reg.LoadTOMLDir(p); err != nil {
				return nil, fmt.Errorf("matchers.extra_paths %q: %w", p, err)
			}
			continue
		}
		if err := reg.LoadTOMLFile(p); err != nil {
			return nil, fmt.Errorf("matchers.extra_paths %q: %w", p, err)
		}
	}
	reg.ApplyFilter(opts.MatcherOnly, opts.MatcherExclude)
	return reg, nil
}

func splitGated(reg *Registry, tech DetectedTech, root string) (active, skipped []string) {
	for _, m := range reg.All() {
		if EvaluateGate(m.Requires(), tech, root) {
			active = append(active, m.Slug())
		} else {
			skipped = append(skipped, m.Slug())
		}
	}
	return
}

func runMatchers(reg *Registry, active []string, content, rel string) []core.CandidateMatch {
	out := make([]core.CandidateMatch, 0)
	activeSet := map[string]struct{}{}
	for _, s := range active {
		activeSet[s] = struct{}{}
	}
	for _, m := range reg.All() {
		if _, ok := activeSet[m.Slug()]; !ok {
			continue
		}
		if !matchesAnyGlob(m.FilePatterns(), rel) {
			continue
		}
		out = append(out, m.Match(content, rel)...)
	}
	return out
}

func matchesAnyGlob(patterns []string, rel string) bool {
	for _, p := range patterns {
		ok, _ := doublestar.PathMatch(p, rel)
		if ok {
			return true
		}
	}
	return false
}

func upsertRecord(root core.DataRoot, projectID, rel, runID, content string, newMatches []core.CandidateMatch) error {
	now := core.NowISO()
	hash := core.FileHashHex([]byte(content))
	existing, err := root.ReadFileRecord(projectID, rel)
	if err != nil {
		return err
	}
	if existing == nil {
		existing = &core.FileRecord{
			FilePath:         rel,
			ProjectID:        projectID,
			Candidates:       []core.CandidateMatch{},
			LastScannedAt:    now,
			LastScannedRunID: runID,
			FileHash:         hash,
			Findings:         []core.Finding{},
			AnalysisHistory:  []core.AnalysisEntry{},
			Status:           core.StatusPending,
		}
	}
	existing.LastScannedAt = now
	existing.LastScannedRunID = runID
	existing.FileHash = hash

	seen := map[string]struct{}{}
	for _, c := range existing.Candidates {
		seen[candidateKey(c)] = struct{}{}
	}
	for _, c := range newMatches {
		if _, ok := seen[candidateKey(c)]; ok {
			continue
		}
		seen[candidateKey(c)] = struct{}{}
		existing.Candidates = append(existing.Candidates, c)
	}
	return root.WriteFileRecord(existing)
}

func candidateKey(c core.CandidateMatch) string {
	var lines []string
	for _, l := range c.LineNumbers {
		lines = append(lines, intToString(l))
	}
	return c.VulnSlug + "|" + c.MatchedPattern + "|" + strings.Join(lines, ",")
}

func intToString(n int) string {
	if n == 0 {
		return "0"
	}
	neg := n < 0
	if neg {
		n = -n
	}
	var buf [20]byte
	i := len(buf)
	for n > 0 {
		i--
		buf[i] = byte('0' + n%10)
		n /= 10
	}
	if neg {
		i--
		buf[i] = '-'
	}
	return string(buf[i:])
}

func langFor(rel string) string {
	switch strings.ToLower(filepath.Ext(rel)) {
	case ".ts", ".tsx":
		return "typescript"
	case ".js", ".jsx", ".mjs", ".cjs":
		return "javascript"
	case ".py":
		return "python"
	case ".rb":
		return "ruby"
	case ".go":
		return "go"
	case ".rs":
		return "rust"
	case ".java":
		return "java"
	case ".kt", ".kts":
		return "kotlin"
	case ".cs":
		return "csharp"
	case ".php":
		return "php"
	case ".swift":
		return "swift"
	case ".ex", ".exs":
		return "elixir"
	case ".erl":
		return "erlang"
	case ".clj", ".cljs":
		return "clojure"
	case ".cr":
		return "crystal"
	case ".scala":
		return "scala"
	case ".c", ".h":
		return "c"
	case ".cpp", ".cc", ".hpp":
		return "cpp"
	case ".dart":
		return "dart"
	}
	return "other"
}

// BatchRecords groups records into directory-coherent batches, splitting
// oversized directories. Mirrors the Rust port's heuristic.
func BatchRecords(records []*core.FileRecord, maxBatch int) [][]*core.FileRecord {
	if maxBatch < 1 {
		maxBatch = 1
	}
	byDir := map[string][]*core.FileRecord{}
	dirs := []string{}
	for _, r := range records {
		d := filepath.Dir(r.FilePath)
		if _, ok := byDir[d]; !ok {
			dirs = append(dirs, d)
		}
		byDir[d] = append(byDir[d], r)
	}
	sort.Strings(dirs)
	out := [][]*core.FileRecord{}
	current := []*core.FileRecord{}
	for _, d := range dirs {
		files := byDir[d]
		for i := 0; i < len(files); i += maxBatch {
			end := i + maxBatch
			if end > len(files) {
				end = len(files)
			}
			chunk := files[i:end]
			if len(current)+len(chunk) <= maxBatch {
				current = append(current, chunk...)
			} else {
				if len(current) > 0 {
					out = append(out, current)
					current = nil
				}
				out = append(out, append([]*core.FileRecord(nil), chunk...))
			}
		}
	}
	if len(current) > 0 {
		out = append(out, current)
	}
	return out
}
