package bench

import (
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/BurntSushi/toml"
	"github.com/noeljackson/deepsec/internal/core"
	"github.com/noeljackson/deepsec/internal/scanner"
)

type ScoreOptions struct {
	TasksDir           string
	OutDir             string
	CandidateExplosion float64
	ExtraMatcherPaths  []string
}

type TaskConfig struct {
	MatcherOnly    []string `toml:"matcher_only"`
	MatcherExclude []string `toml:"matcher_exclude"`
}

type Summary struct {
	GeneratedAt              string             `json:"generated_at"`
	TaskCount                int                `json:"task_count"`
	ScannerRecall            float64            `json:"scanner_recall"`
	RecallCritical           float64            `json:"recall_critical"`
	RecallHigh               float64            `json:"recall_high"`
	RecallMedium             float64            `json:"recall_medium"`
	RecallLow                float64            `json:"recall_low"`
	ScannerPrecision         float64            `json:"scanner_precision"`
	CandidateCountTotal      int                `json:"candidate_count_total"`
	CandidateCountNoisy      int                `json:"candidate_count_noisy"`
	FalsePositiveDecoyRate   float64            `json:"false_positive_decoy_rate"`
	CandidateDensity         float64            `json:"candidate_density"`
	RecallBySeverity         map[string]float64 `json:"recall_by_severity"`
	ScannerPrecisionBySlug   map[string]float64 `json:"scanner_precision_by_slug"`
	FalsePositivesBySlug     map[string]int     `json:"false_positive_by_slug"`
	FalseNegativesBySlug     map[string]int     `json:"false_negative_by_slug"`
	ScannerUncoveredIssues   int                `json:"scanner_uncovered_issues"`
	OutputDir                string             `json:"output_dir"`
	CandidateExplosionThresh float64            `json:"candidate_explosion_threshold"`
}

type RunResult struct {
	Summary             Summary              `json:"summary"`
	Tasks               []TaskResult         `json:"tasks"`
	BySlug              []SlugResult         `json:"by_slug"`
	FalsePositives      []FalsePositive      `json:"false_positives"`
	FalseNegatives      []FalseNegative      `json:"false_negatives"`
	CandidateExplosions []CandidateExplosion `json:"candidate_explosion"`
}

type TaskResult struct {
	TaskID                 string  `json:"task_id"`
	FilesScanned           int     `json:"files_scanned"`
	LOC                    int     `json:"loc"`
	ScannerRecall          float64 `json:"scanner_recall"`
	RecallCritical         float64 `json:"recall_critical"`
	RecallHigh             float64 `json:"recall_high"`
	RecallMedium           float64 `json:"recall_medium"`
	RecallLow              float64 `json:"recall_low"`
	ScannerPrecision       float64 `json:"scanner_precision"`
	CandidateCountTotal    int     `json:"candidate_count_total"`
	CandidateCountNoisy    int     `json:"candidate_count_noisy"`
	FalsePositiveDecoyRate float64 `json:"false_positive_decoy_rate"`
	CandidateDensity       float64 `json:"candidate_density"`
	DetectableIssues       int     `json:"detectable_issues"`
	MatchedIssues          int     `json:"matched_issues"`
	UncoveredIssues        int     `json:"uncovered_issues"`
	DecoyCount             int     `json:"decoy_count"`
	FlaggedDecoys          int     `json:"flagged_decoys"`
}

type SlugResult struct {
	TaskID          string  `json:"task_id"`
	Slug            string  `json:"slug"`
	TruePositive    int     `json:"true_positive"`
	FalsePositive   int     `json:"false_positive"`
	FalseNegative   int     `json:"false_negative"`
	Precision       float64 `json:"precision"`
	CandidateCount  int     `json:"candidate_count"`
	NoisyCandidates int     `json:"noisy_candidates"`
}

type FalsePositive struct {
	TaskID      string `json:"task_id"`
	File        string `json:"file"`
	Line        int    `json:"line"`
	Slug        string `json:"slug"`
	Contradicts string `json:"contradicts"`
	Snippet     string `json:"snippet,omitempty"`
	Matched     string `json:"matched,omitempty"`
}

type FalseNegative struct {
	TaskID           string   `json:"task_id"`
	IssueID          string   `json:"issue_id"`
	File             string   `json:"file"`
	StartLine        int      `json:"start_line"`
	EndLine          int      `json:"end_line"`
	VulnSlugs        []string `json:"vuln_slugs"`
	ClosestCandidate string   `json:"closest_candidate,omitempty"`
	Reason           string   `json:"reason"`
}

type CandidateExplosion struct {
	TaskID       string  `json:"task_id"`
	File         string  `json:"file"`
	LOC          int     `json:"loc"`
	Candidates   int     `json:"candidates"`
	PerKLOC      float64 `json:"per_kloc"`
	ThresholdKLO float64 `json:"threshold_per_kloc"`
}

type candidateRef struct {
	File string
	core.CandidateMatch
}

func Score(taskIDs []string, opts ScoreOptions) (*RunResult, error) {
	if opts.TasksDir == "" {
		opts.TasksDir = filepath.Join("bench", "tasks")
	}
	if opts.OutDir == "" {
		opts.OutDir = filepath.Join("bench", "out")
	}
	if opts.CandidateExplosion == 0 {
		opts.CandidateExplosion = 100
	}
	if len(taskIDs) == 0 {
		ids, err := discoverTasks(opts.TasksDir)
		if err != nil {
			return nil, err
		}
		taskIDs = ids
	}

	reg, err := scanner.WithBuiltin()
	if err != nil {
		return nil, err
	}
	for _, p := range opts.ExtraMatcherPaths {
		info, err := os.Stat(p)
		if err != nil {
			return nil, fmt.Errorf("extra matcher path %q: %w", p, err)
		}
		if info.IsDir() {
			if err := reg.LoadTOMLDir(p); err != nil {
				return nil, fmt.Errorf("extra matcher path %q: %w", p, err)
			}
			continue
		}
		if err := reg.LoadTOMLFile(p); err != nil {
			return nil, fmt.Errorf("extra matcher path %q: %w", p, err)
		}
	}
	noise := map[string]scanner.NoiseTier{}
	for _, m := range reg.All() {
		noise[m.Slug()] = m.NoiseTier()
	}

	now := time.Now().UTC().Format("20060102T150405Z")
	outDir := filepath.Join(opts.OutDir, now)
	result := &RunResult{}
	agg := accumulator{}
	for _, id := range taskIDs {
		tr, err := scoreTask(id, opts.TasksDir, outDir, opts.CandidateExplosion, noise, opts.ExtraMatcherPaths)
		if err != nil {
			return nil, err
		}
		result.Tasks = append(result.Tasks, tr.Task)
		result.BySlug = append(result.BySlug, tr.BySlug...)
		result.FalsePositives = append(result.FalsePositives, tr.FalsePositives...)
		result.FalseNegatives = append(result.FalseNegatives, tr.FalseNegatives...)
		result.CandidateExplosions = append(result.CandidateExplosions, tr.CandidateExplosions...)
		agg.add(tr)
	}
	result.Summary = agg.summary(now, outDir, opts.CandidateExplosion)
	result.Summary.TaskCount = len(result.Tasks)
	if err := writeReports(outDir, result); err != nil {
		return nil, err
	}
	return result, nil
}

type scoredTask struct {
	Task                TaskResult
	BySlug              []SlugResult
	FalsePositives      []FalsePositive
	FalseNegatives      []FalseNegative
	CandidateExplosions []CandidateExplosion
	denom               map[core.Severity]int
	hits                map[core.Severity]int
	slugTP              map[string]int
	slugFP              map[string]int
	slugFN              map[string]int
	slugCandidates      map[string]int
	slugNoisy           map[string]int
}

func scoreTask(id, tasksDir, outDir string, explosionThreshold float64, noise map[string]scanner.NoiseTier, extraMatcherPaths []string) (scoredTask, error) {
	taskDir := filepath.Join(tasksDir, id)
	source := filepath.Join(taskDir, "source")
	key, err := LoadAnswerKey(filepath.Join(taskDir, "answer.yaml"))
	if err != nil {
		return scoredTask{}, err
	}
	cfg, err := loadTaskConfig(filepath.Join(taskDir, "task.toml"))
	if err != nil {
		return scoredTask{}, err
	}
	dataDir, err := os.MkdirTemp("", "deepsec-bench-"+id+"-")
	if err != nil {
		return scoredTask{}, err
	}
	defer os.RemoveAll(dataDir)

	outcome, err := scanner.Scan(scanner.Options{
		ProjectID:         id,
		Root:              source,
		DataRoot:          core.DataRootFromPath(dataDir),
		MatcherOnly:       cfg.MatcherOnly,
		MatcherExclude:    cfg.MatcherExclude,
		ExtraMatcherPaths: extraMatcherPaths,
	})
	if err != nil {
		return scoredTask{}, err
	}
	records, err := core.DataRootFromPath(dataDir).LoadAllFileRecords(id)
	if err != nil {
		return scoredTask{}, err
	}

	locByFile, totalLOC := countLOC(source)
	candidates := flattenCandidates(records)
	matchedIssues := map[string]bool{}
	task := scoredTask{
		denom:          map[core.Severity]int{},
		hits:           map[core.Severity]int{},
		slugTP:         map[string]int{},
		slugFP:         map[string]int{},
		slugFN:         map[string]int{},
		slugCandidates: map[string]int{},
		slugNoisy:      map[string]int{},
	}
	for _, issue := range key.Issues {
		if !issue.Scanner.MustEmitCandidate {
			task.Task.UncoveredIssues++
			continue
		}
		task.Task.DetectableIssues++
		task.denom[issue.Severity]++
		if matchIssue(issue, candidates) != nil {
			matchedIssues[issue.ID] = true
			task.Task.MatchedIssues++
			task.hits[issue.Severity]++
		} else {
			task.slugFN[issue.VulnSlugs[0]]++
			task.FalseNegatives = append(task.FalseNegatives, falseNegative(id, issue, candidates))
		}
	}
	flaggedDecoys := map[string]bool{}
	for _, c := range candidates {
		line := firstLine(c.LineNumbers)
		task.slugCandidates[c.VulnSlug]++
		if noise[c.VulnSlug] == scanner.NoiseNoisy {
			task.Task.CandidateCountNoisy++
			task.slugNoisy[c.VulnSlug]++
		}
		if matchingIssueForCandidate(c, key.Issues) != nil {
			task.slugTP[c.VulnSlug]++
			continue
		}
		contradicts := "no entry"
		for _, d := range key.Decoys {
			if decoyMatches(d, c) {
				contradicts = d.ID
				flaggedDecoys[d.ID] = true
				break
			}
		}
		task.slugFP[c.VulnSlug]++
		task.FalsePositives = append(task.FalsePositives, FalsePositive{
			TaskID:      id,
			File:        c.File,
			Line:        line,
			Slug:        c.VulnSlug,
			Contradicts: contradicts,
			Snippet:     c.Snippet,
			Matched:     c.MatchedPattern,
		})
	}

	task.Task = TaskResult{
		TaskID:                 id,
		FilesScanned:           outcome.FilesScanned,
		LOC:                    totalLOC,
		ScannerRecall:          rate(task.Task.MatchedIssues, task.Task.DetectableIssues),
		RecallCritical:         rate(task.hits[core.SeverityCritical], task.denom[core.SeverityCritical]),
		RecallHigh:             rate(task.hits[core.SeverityHigh], task.denom[core.SeverityHigh]),
		RecallMedium:           rate(task.hits[core.SeverityMedium], task.denom[core.SeverityMedium]),
		RecallLow:              rate(task.hits[core.SeverityLow], task.denom[core.SeverityLow]),
		ScannerPrecision:       rate(sumMap(task.slugTP), len(candidates)),
		CandidateCountTotal:    len(candidates),
		CandidateCountNoisy:    task.Task.CandidateCountNoisy,
		FalsePositiveDecoyRate: rate(len(flaggedDecoys), len(key.Decoys)),
		CandidateDensity:       density(len(candidates), totalLOC),
		DetectableIssues:       task.Task.DetectableIssues,
		MatchedIssues:          task.Task.MatchedIssues,
		UncoveredIssues:        task.Task.UncoveredIssues,
		DecoyCount:             len(key.Decoys),
		FlaggedDecoys:          len(flaggedDecoys),
	}
	for slug := range task.slugCandidates {
		task.BySlug = append(task.BySlug, SlugResult{
			TaskID:          id,
			Slug:            slug,
			TruePositive:    task.slugTP[slug],
			FalsePositive:   task.slugFP[slug],
			FalseNegative:   task.slugFN[slug],
			Precision:       rate(task.slugTP[slug], task.slugCandidates[slug]),
			CandidateCount:  task.slugCandidates[slug],
			NoisyCandidates: task.slugNoisy[slug],
		})
	}
	for slug, fn := range task.slugFN {
		if _, ok := task.slugCandidates[slug]; !ok {
			task.BySlug = append(task.BySlug, SlugResult{TaskID: id, Slug: slug, FalseNegative: fn})
		}
	}
	sort.Slice(task.BySlug, func(i, j int) bool { return task.BySlug[i].Slug < task.BySlug[j].Slug })
	for file, loc := range locByFile {
		n := countCandidatesInFile(candidates, file)
		per := density(n, loc)
		if per > explosionThreshold {
			task.CandidateExplosions = append(task.CandidateExplosions, CandidateExplosion{
				TaskID: id, File: file, LOC: loc, Candidates: n, PerKLOC: per, ThresholdKLO: explosionThreshold,
			})
		}
	}
	_ = matchedIssues
	return task, nil
}

func loadTaskConfig(path string) (TaskConfig, error) {
	var cfg TaskConfig
	if _, err := os.Stat(path); err != nil {
		if os.IsNotExist(err) {
			return cfg, nil
		}
		return cfg, err
	}
	_, err := toml.DecodeFile(path, &cfg)
	return cfg, err
}

func flattenCandidates(records []*core.FileRecord) []candidateRef {
	var out []candidateRef
	for _, r := range records {
		for _, c := range r.Candidates {
			out = append(out, candidateRef{File: r.FilePath, CandidateMatch: c})
		}
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].File != out[j].File {
			return out[i].File < out[j].File
		}
		return firstLine(out[i].LineNumbers) < firstLine(out[j].LineNumbers)
	})
	return out
}

func matchIssue(issue Issue, candidates []candidateRef) *candidateRef {
	for i := range candidates {
		if candidateMatchesIssue(candidates[i], issue) {
			return &candidates[i]
		}
	}
	return nil
}

func matchingIssueForCandidate(c candidateRef, issues []Issue) *Issue {
	for i := range issues {
		if issues[i].Scanner.MustEmitCandidate && candidateMatchesIssue(c, issues[i]) {
			return &issues[i]
		}
	}
	return nil
}

func candidateMatchesIssue(c candidateRef, issue Issue) bool {
	if c.File != issue.File || !SlugMatches(c.VulnSlug, issue.VulnSlugs) {
		return false
	}
	for _, line := range c.LineNumbers {
		if issue.Location.Contains(line) {
			return true
		}
	}
	return false
}

func decoyMatches(d Decoy, c candidateRef) bool {
	if c.File != d.File || !SlugMatches(c.VulnSlug, d.ForbiddenSlugs) {
		return false
	}
	for _, line := range c.LineNumbers {
		if line == d.Line {
			return true
		}
	}
	return false
}

func falseNegative(taskID string, issue Issue, candidates []candidateRef) FalseNegative {
	closest := ""
	reason := "no candidate with acceptable slug near issue"
	best := math.MaxInt
	for _, c := range candidates {
		if c.File != issue.File {
			continue
		}
		dist := distanceToRange(firstLine(c.LineNumbers), issue.Location)
		if dist < best {
			best = dist
			closest = fmt.Sprintf("%s:%d:%s", c.File, firstLine(c.LineNumbers), c.VulnSlug)
			if !SlugMatches(c.VulnSlug, issue.VulnSlugs) {
				reason = "closest candidate has a non-acceptable slug"
			} else {
				reason = "closest acceptable-slug candidate is outside tolerance"
			}
		}
	}
	return FalseNegative{
		TaskID: taskID, IssueID: issue.ID, File: issue.File,
		StartLine: issue.Location.StartLine, EndLine: issue.Location.EndLine,
		VulnSlugs: issue.VulnSlugs, ClosestCandidate: closest, Reason: reason,
	}
}

func distanceToRange(line int, loc Location) int {
	if loc.Contains(line) {
		return 0
	}
	if line < loc.StartLine-loc.ToleranceOrDefault() {
		return loc.StartLine - loc.ToleranceOrDefault() - line
	}
	return line - (loc.EndLine + loc.ToleranceOrDefault())
}

func discoverTasks(tasksDir string) ([]string, error) {
	entries, err := os.ReadDir(tasksDir)
	if err != nil {
		return nil, err
	}
	var out []string
	for _, e := range entries {
		if !e.IsDir() {
			continue
		}
		if _, err := os.Stat(filepath.Join(tasksDir, e.Name(), "answer.yaml")); err == nil {
			out = append(out, e.Name())
		}
	}
	sort.Strings(out)
	return out, nil
}

func countLOC(root string) (map[string]int, int) {
	out := map[string]int{}
	total := 0
	filepath.WalkDir(root, func(path string, d os.DirEntry, err error) error {
		if err != nil || d.IsDir() {
			return nil
		}
		body, err := os.ReadFile(path)
		if err != nil {
			return nil
		}
		rel, err := filepath.Rel(root, path)
		if err != nil {
			return nil
		}
		rel = filepath.ToSlash(rel)
		loc := len(strings.Split(strings.TrimRight(string(body), "\n"), "\n"))
		if len(body) == 0 {
			loc = 0
		}
		out[rel] = loc
		total += loc
		return nil
	})
	return out, total
}

func countCandidatesInFile(candidates []candidateRef, file string) int {
	n := 0
	for _, c := range candidates {
		if c.File == file {
			n++
		}
	}
	return n
}

func writeReports(outDir string, result *RunResult) error {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(outDir, "summary.json"), result.Summary); err != nil {
		return err
	}
	if err := writeTSV(filepath.Join(outDir, "by_task.tsv"), byTaskRows(result.Tasks)); err != nil {
		return err
	}
	if err := writeTSV(filepath.Join(outDir, "by_slug.tsv"), bySlugRows(result.BySlug)); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(outDir, "false_positives.json"), result.FalsePositives); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(outDir, "false_negatives.json"), result.FalseNegatives); err != nil {
		return err
	}
	return writeJSON(filepath.Join(outDir, "candidate_explosion.json"), result.CandidateExplosions)
}

func writeJSON(path string, v any) error {
	body, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	body = append(body, '\n')
	return os.WriteFile(path, body, 0o644)
}

func writeTSV(path string, rows [][]string) error {
	var b strings.Builder
	for _, row := range rows {
		b.WriteString(strings.Join(row, "\t"))
		b.WriteByte('\n')
	}
	return os.WriteFile(path, []byte(b.String()), 0o644)
}

func byTaskRows(tasks []TaskResult) [][]string {
	rows := [][]string{{"task_id", "files_scanned", "loc", "scanner_recall", "scanner_precision", "candidate_count_total", "candidate_count_noisy", "false_positive_decoy_rate", "candidate_density"}}
	for _, t := range tasks {
		rows = append(rows, []string{t.TaskID, itoa(t.FilesScanned), itoa(t.LOC), ftoa(t.ScannerRecall), ftoa(t.ScannerPrecision), itoa(t.CandidateCountTotal), itoa(t.CandidateCountNoisy), ftoa(t.FalsePositiveDecoyRate), ftoa(t.CandidateDensity)})
	}
	return rows
}

func bySlugRows(slugs []SlugResult) [][]string {
	rows := [][]string{{"task_id", "slug", "true_positive", "false_positive", "false_negative", "precision", "candidate_count", "noisy_candidates"}}
	for _, s := range slugs {
		rows = append(rows, []string{s.TaskID, s.Slug, itoa(s.TruePositive), itoa(s.FalsePositive), itoa(s.FalseNegative), ftoa(s.Precision), itoa(s.CandidateCount), itoa(s.NoisyCandidates)})
	}
	return rows
}

type accumulator struct {
	detectable int
	matched    int
	denom      map[core.Severity]int
	hits       map[core.Severity]int
	candidates int
	noisy      int
	decoys     int
	flagged    int
	loc        int
	uncovered  int
	slugTP     map[string]int
	slugFP     map[string]int
	slugFN     map[string]int
	slugCand   map[string]int
}

func (a *accumulator) add(t scoredTask) {
	if a.denom == nil {
		a.denom, a.hits = map[core.Severity]int{}, map[core.Severity]int{}
		a.slugTP, a.slugFP, a.slugFN, a.slugCand = map[string]int{}, map[string]int{}, map[string]int{}, map[string]int{}
	}
	a.detectable += t.Task.DetectableIssues
	a.matched += t.Task.MatchedIssues
	a.candidates += t.Task.CandidateCountTotal
	a.noisy += t.Task.CandidateCountNoisy
	a.decoys += t.Task.DecoyCount
	a.flagged += t.Task.FlaggedDecoys
	a.loc += t.Task.LOC
	a.uncovered += t.Task.UncoveredIssues
	for sev, n := range t.denom {
		a.denom[sev] += n
	}
	for sev, n := range t.hits {
		a.hits[sev] += n
	}
	for slug, n := range t.slugTP {
		a.slugTP[slug] += n
	}
	for slug, n := range t.slugFP {
		a.slugFP[slug] += n
	}
	for slug, n := range t.slugFN {
		a.slugFN[slug] += n
	}
	for slug, n := range t.slugCandidates {
		a.slugCand[slug] += n
	}
}

func (a accumulator) summary(ts, outDir string, threshold float64) Summary {
	precisionBySlug := map[string]float64{}
	for slug, n := range a.slugCand {
		precisionBySlug[slug] = rate(a.slugTP[slug], n)
	}
	return Summary{
		GeneratedAt:              ts,
		ScannerRecall:            rate(a.matched, a.detectable),
		RecallCritical:           rate(a.hits[core.SeverityCritical], a.denom[core.SeverityCritical]),
		RecallHigh:               rate(a.hits[core.SeverityHigh], a.denom[core.SeverityHigh]),
		RecallMedium:             rate(a.hits[core.SeverityMedium], a.denom[core.SeverityMedium]),
		RecallLow:                rate(a.hits[core.SeverityLow], a.denom[core.SeverityLow]),
		ScannerPrecision:         rate(sumMap(a.slugTP), a.candidates),
		CandidateCountTotal:      a.candidates,
		CandidateCountNoisy:      a.noisy,
		FalsePositiveDecoyRate:   rate(a.flagged, a.decoys),
		CandidateDensity:         density(a.candidates, a.loc),
		RecallBySeverity:         map[string]float64{"CRITICAL": rate(a.hits[core.SeverityCritical], a.denom[core.SeverityCritical]), "HIGH": rate(a.hits[core.SeverityHigh], a.denom[core.SeverityHigh]), "MEDIUM": rate(a.hits[core.SeverityMedium], a.denom[core.SeverityMedium]), "LOW": rate(a.hits[core.SeverityLow], a.denom[core.SeverityLow])},
		ScannerPrecisionBySlug:   precisionBySlug,
		FalsePositivesBySlug:     a.slugFP,
		FalseNegativesBySlug:     a.slugFN,
		ScannerUncoveredIssues:   a.uncovered,
		OutputDir:                outDir,
		CandidateExplosionThresh: threshold,
	}
}

func rate(num, den int) float64 {
	if den == 0 {
		return 0
	}
	return float64(num) / float64(den)
}

func density(candidates, loc int) float64 {
	if loc == 0 {
		return 0
	}
	return float64(candidates) / (float64(loc) / 1000)
}

func sumMap(m map[string]int) int {
	n := 0
	for _, v := range m {
		n += v
	}
	return n
}

func firstLine(lines []int) int {
	if len(lines) == 0 {
		return 0
	}
	return lines[0]
}

func itoa(n int) string { return fmt.Sprintf("%d", n) }
func ftoa(n float64) string {
	return fmt.Sprintf("%.6f", n)
}
