package scanner

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/bmatcuk/doublestar/v4"
	"github.com/noeljackson/deepsec/internal/core"
	scannerast "github.com/noeljackson/deepsec/internal/scanner/ast"
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
	// ForceRescan disables the file-hash cache. When true, every file is
	// re-evaluated even when both its content and the matcher pack are
	// unchanged since the last scan.
	ForceRescan bool
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
	CacheHits       int
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
	CacheHits       int
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
	astRT, err := runtimeForActiveAST(active, reg)
	if err != nil {
		return nil, err
	}
	if astRT != nil {
		defer astRT.Close(context.Background())
	}

	files, err := WalkProject(opts.Root)
	if err != nil {
		return nil, err
	}

	packHash := reg.PackHash()
	candidateCount := 0
	cacheHits := 0
	byLang := map[string]*LanguageStat{}
	for _, rel := range files {
		abs := filepath.Join(opts.Root, rel)
		body, err := os.ReadFile(abs)
		if err != nil {
			continue
		}
		content := strings.ReplaceAll(string(body), "\r\n", "\n")
		fileHash := core.FileHashHex([]byte(content))
		lang := langFor(rel)
		st, ok := byLang[lang]
		if !ok {
			st = &LanguageStat{Language: lang}
			byLang[lang] = st
		}
		st.FilesScanned++
		cached, hit, err := cachedCandidates(opts, rel, fileHash, packHash)
		if err != nil {
			return nil, err
		}
		var matches []core.CandidateMatch
		if hit {
			matches = cached
			cacheHits++
		} else {
			matches = runMatchers(reg, active, content, rel, astRT)
		}
		if len(matches) > 0 {
			st.FilesWithMatch++
		}
		candidateCount += len(matches)
		if hit {
			if err := touchRecord(opts.DataRoot, opts.ProjectID, rel, runID, fileHash, packHash); err != nil {
				return nil, err
			}
			continue
		}
		if err := upsertRecord(opts.DataRoot, opts.ProjectID, rel, runID, content, packHash, matches); err != nil {
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
		CacheHits:       cacheHits,
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
	astRT, err := runtimeForActiveAST(active, reg)
	if err != nil {
		return nil, err
	}
	if astRT != nil {
		defer astRT.Close(context.Background())
	}

	packHash := reg.PackHash()
	candidateCount := 0
	cacheHits := 0
	for _, rel := range files {
		abs := filepath.Join(opts.Root, rel)
		body, _ := os.ReadFile(abs)
		content := strings.ReplaceAll(string(body), "\r\n", "\n")
		fileHash := core.FileHashHex([]byte(content))
		cached, hit, err := cachedCandidates(opts, rel, fileHash, packHash)
		if err != nil {
			return nil, err
		}
		var matches []core.CandidateMatch
		if hit {
			matches = cached
			cacheHits++
		} else {
			matches = runMatchers(reg, active, content, rel, astRT)
		}
		candidateCount += len(matches)
		if hit {
			if err := touchRecord(opts.DataRoot, opts.ProjectID, rel, runID, fileHash, packHash); err != nil {
				return nil, err
			}
			continue
		}
		if err := upsertRecord(opts.DataRoot, opts.ProjectID, rel, runID, content, packHash, matches); err != nil {
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
		CacheHits:       cacheHits,
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

func runtimeForActiveAST(active []string, reg *Registry) (*scannerast.Runtime, error) {
	if !reg.HasASTPatterns() {
		return nil, nil
	}
	activeSet := map[string]struct{}{}
	for _, slug := range active {
		activeSet[slug] = struct{}{}
	}
	for _, m := range reg.All() {
		if _, ok := activeSet[m.Slug()]; ok && m.HasASTPatterns() {
			return scannerast.NewRuntime(context.Background(), scannerast.DefaultGrammars())
		}
	}
	return nil, nil
}

func runMatchers(reg *Registry, active []string, content, rel string, astRT *scannerast.Runtime) []core.CandidateMatch {
	out := make([]core.CandidateMatch, 0)
	activeSet := map[string]struct{}{}
	for _, s := range active {
		activeSet[s] = struct{}{}
	}
	astLang := scannerast.LanguageForPath(rel)
	type astPlan struct {
		matcher  *Matcher
		patterns []compiledASTPattern
	}
	var astPlans []astPlan
	for _, m := range reg.All() {
		if _, ok := activeSet[m.Slug()]; !ok {
			continue
		}
		if !matchesAnyGlob(m.FilePatterns(), rel) {
			continue
		}
		if astRT == nil || astLang == "" || !m.HasASTLanguage(astLang) {
			out = append(out, m.Match(content, rel)...)
			continue
		}
		patterns := m.EligibleASTPatterns(content, rel, astLang)
		if len(patterns) > 0 {
			astPlans = append(astPlans, astPlan{matcher: m, patterns: patterns})
		}
	}
	if len(astPlans) == 0 {
		return dedupeCandidates(out)
	}
	tree, err := astRT.Parse(context.Background(), astLang, []byte(content), rel)
	if err != nil {
		if errors.Is(err, scannerast.ErrLanguageUnavailable) {
			return dedupeCandidates(out)
		}
		return dedupeCandidates(out)
	}
	defer tree.Close()
	for _, plan := range astPlans {
		out = append(out, plan.matcher.MatchAST(tree, rel, plan.patterns)...)
	}
	return dedupeCandidates(out)
}

func dedupeCandidates(in []core.CandidateMatch) []core.CandidateMatch {
	if len(in) < 2 {
		return in
	}
	seen := map[string]struct{}{}
	out := make([]core.CandidateMatch, 0, len(in))
	for _, c := range in {
		key := candidateKey(c)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		out = append(out, c)
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

func upsertRecord(root core.DataRoot, projectID, rel, runID, content, matcherPackHash string, newMatches []core.CandidateMatch) error {
	now := core.NowISO()
	hash := core.FileHashHex([]byte(content))
	existing, err := root.ReadFileRecord(projectID, rel)
	if err != nil {
		return err
	}
	if existing == nil {
		existing = &core.FileRecord{
			FilePath:            rel,
			ProjectID:           projectID,
			Candidates:          []core.CandidateMatch{},
			LastScannedAt:       now,
			LastScannedRunID:    runID,
			FileHash:            hash,
			LastMatcherPackHash: matcherPackHash,
			Findings:            []core.Finding{},
			AnalysisHistory:     []core.AnalysisEntry{},
			Status:              core.StatusPending,
		}
	}
	existing.LastScannedAt = now
	existing.LastScannedRunID = runID
	existing.FileHash = hash
	existing.LastMatcherPackHash = matcherPackHash

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

// cachedCandidates returns this file's existing candidates if the file
// content hash AND the matcher pack hash both match the previous scan.
// `hit` is true exactly when the caller should skip matcher execution.
// `--force-rescan` (opts.ForceRescan) always returns hit=false.
func cachedCandidates(opts Options, rel, fileHash, packHash string) ([]core.CandidateMatch, bool, error) {
	if opts.ForceRescan {
		return nil, false, nil
	}
	existing, err := opts.DataRoot.ReadFileRecord(opts.ProjectID, rel)
	if err != nil {
		return nil, false, err
	}
	if existing == nil {
		return nil, false, nil
	}
	if existing.FileHash != fileHash {
		return nil, false, nil
	}
	if existing.LastMatcherPackHash != packHash {
		return nil, false, nil
	}
	return existing.Candidates, true, nil
}

// touchRecord updates LastScannedAt/RunID/FileHash/LastMatcherPackHash
// for a cache hit without rewriting Candidates or other fields.
func touchRecord(root core.DataRoot, projectID, rel, runID, fileHash, packHash string) error {
	existing, err := root.ReadFileRecord(projectID, rel)
	if err != nil {
		return err
	}
	if existing == nil {
		// Should not happen for a cache hit, but be defensive.
		return nil
	}
	existing.LastScannedAt = core.NowISO()
	existing.LastScannedRunID = runID
	existing.FileHash = fileHash
	existing.LastMatcherPackHash = packHash
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
