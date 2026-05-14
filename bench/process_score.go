package bench

import (
	"context"
	"encoding/json"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"

	"github.com/noeljackson/deepsec/internal/core"
	"github.com/noeljackson/deepsec/internal/processor"
	"github.com/noeljackson/deepsec/internal/processor/mockbackend"
	"gopkg.in/yaml.v3"
)

type ProcessScoreOptions struct {
	TasksDir         string
	OutDir           string
	Now              string
	Repeat           int
	Seed             uint64
	BootstrapSamples int
	// CorePromptPath, when set, replaces the bundled core.md prompt for
	// each task. Used by the prompt-evolution harness (#86).
	CorePromptPath string
}

type ProcessorAnswerKey struct {
	Findings            []ProcessorAnswerFinding `yaml:"findings"`
	ExpectedRefusals    *int                     `yaml:"expected_refusals,omitempty"`
	ExpectedFindingsMin *int                     `yaml:"expected_findings_min,omitempty"`
}

type ProcessorAnswerFinding struct {
	ID        string                      `yaml:"id"`
	File      string                      `yaml:"file"`
	VulnSlugs []string                    `yaml:"vulnSlugs"`
	Severity  core.Severity               `yaml:"severity"`
	Location  Location                    `yaml:"location"`
	Processor ProcessorFindingExpectation `yaml:"processor"`
}

type ProcessorFindingExpectation struct {
	MustReportFinding *bool `yaml:"mustReportFinding"`
}

type ProcessRunResult struct {
	Summary            ProcessSummary            `json:"summary"`
	Tasks              []ProcessTaskResult       `json:"tasks"`
	BySlug             []ProcessSlugResult       `json:"by_slug"`
	FalsePositives     []ProcessFalsePositive    `json:"false_positives"`
	FalseNegatives     []ProcessFalseNegative    `json:"false_negatives"`
	SeverityMismatches []ProcessSeverityMismatch `json:"severity_mismatches"`
}

type ProcessSummary struct {
	GeneratedAt                   string             `json:"generated_at"`
	TaskCount                     int                `json:"task_count"`
	ProcessorPrecision            float64            `json:"processor_precision"`
	ProcessorRecallGivenCandidate float64            `json:"processor_recall_given_candidate"`
	ProcessorRecall               float64            `json:"processor_recall"`
	SeverityAccuracy              float64            `json:"severity_accuracy"`
	RefusalRate                   float64            `json:"refusal_rate"`
	FalsePositiveCount            int                `json:"false_positive_count"`
	FalseNegativeCount            int                `json:"false_negative_count"`
	PerSlugPrecision              map[string]float64 `json:"per_slug_precision"`
	PerSlugRecall                 map[string]float64 `json:"per_slug_recall"`
	OutputDir                     string             `json:"output_dir"`
}

type ProcessTaskResult struct {
	TaskID                        string  `json:"task_id"`
	ProcessorPrecision            float64 `json:"processor_precision"`
	ProcessorRecallGivenCandidate float64 `json:"processor_recall_given_candidate"`
	ProcessorRecall               float64 `json:"processor_recall"`
	SeverityAccuracy              float64 `json:"severity_accuracy"`
	RefusalRate                   float64 `json:"refusal_rate"`
	ProducedFindings              int     `json:"produced_findings"`
	MatchedFindings               int     `json:"matched_findings"`
	CandidateBackedFindings       int     `json:"candidate_backed_findings"`
	CandidateBackedMatched        int     `json:"candidate_backed_matched"`
	ExpectedFindings              int     `json:"expected_findings"`
	FalsePositiveCount            int     `json:"false_positive_count"`
	FalseNegativeCount            int     `json:"false_negative_count"`
	RefusalCount                  int     `json:"refusal_count"`
	BatchCount                    int     `json:"batch_count"`
}

type ProcessSlugResult struct {
	TaskID        string  `json:"task_id"`
	Slug          string  `json:"slug"`
	TruePositive  int     `json:"true_positive"`
	FalsePositive int     `json:"false_positive"`
	FalseNegative int     `json:"false_negative"`
	Precision     float64 `json:"precision"`
	Recall        float64 `json:"recall"`
}

type ProcessFalsePositive struct {
	TaskID        string `json:"task_id"`
	File          string `json:"file"`
	Line          int    `json:"line"`
	Slug          string `json:"slug"`
	ClosestAnswer string `json:"closest_answer,omitempty"`
	Title         string `json:"title,omitempty"`
}

type ProcessFalseNegative struct {
	TaskID        string                `json:"task_id"`
	FindingID     string                `json:"finding_id"`
	File          string                `json:"file"`
	StartLine     int                   `json:"start_line"`
	EndLine       int                   `json:"end_line"`
	VulnSlugs     []string              `json:"vuln_slugs"`
	Candidates    []core.CandidateMatch `json:"candidates,omitempty"`
	ResponseIndex int                   `json:"response_index,omitempty"`
}

type ProcessSeverityMismatch struct {
	TaskID   string        `json:"task_id"`
	ID       string        `json:"id"`
	File     string        `json:"file"`
	Slug     string        `json:"slug"`
	Expected core.Severity `json:"expected"`
	Actual   core.Severity `json:"actual"`
}

type producedFindingRef struct {
	File string
	core.Finding
}

func ProcessScore(taskIDs []string, opts ProcessScoreOptions) (*ProcessRunResult, error) {
	if opts.Repeat > 1 {
		repeated, err := ProcessScoreRepeated(taskIDs, opts)
		if err != nil {
			return nil, err
		}
		return repeated.LastRun, nil
	}
	if opts.TasksDir == "" {
		opts.TasksDir = filepath.Join("bench", "processor-fixtures")
	}
	if opts.OutDir == "" {
		opts.OutDir = filepath.Join("bench", "out-processor")
	}
	now := opts.Now
	if now == "" {
		now = time.Now().UTC().Format("20060102T150405Z")
	}
	if len(taskIDs) == 0 {
		ids, err := discoverTasks(opts.TasksDir)
		if err != nil {
			return nil, err
		}
		taskIDs = ids
	}
	opts.Now = now
	return processScoreOnce(taskIDs, opts, filepath.Join(opts.OutDir, now), opts.Seed)
}

func processScoreOnce(taskIDs []string, opts ProcessScoreOptions, outDir string, seed uint64) (*ProcessRunResult, error) {
	result := &ProcessRunResult{}
	agg := processAccumulator{
		slugTP: map[string]int{}, slugFP: map[string]int{}, slugFN: map[string]int{},
	}
	var corePromptOverride string
	if opts.CorePromptPath != "" {
		b, err := os.ReadFile(opts.CorePromptPath)
		if err != nil {
			return nil, fmt.Errorf("read core-prompt %q: %w", opts.CorePromptPath, err)
		}
		corePromptOverride = string(b)
	}
	for _, id := range taskIDs {
		task, err := processScoreTask(id, opts.TasksDir, seed, corePromptOverride)
		if err != nil {
			return nil, err
		}
		result.Tasks = append(result.Tasks, task.Task)
		result.BySlug = append(result.BySlug, task.BySlug...)
		result.FalsePositives = append(result.FalsePositives, task.FalsePositives...)
		result.FalseNegatives = append(result.FalseNegatives, task.FalseNegatives...)
		result.SeverityMismatches = append(result.SeverityMismatches, task.SeverityMismatches...)
		agg.add(task)
	}
	result.Summary = agg.summary(opts.Now, outDir)
	result.Summary.TaskCount = len(result.Tasks)
	if err := writeProcessReports(outDir, result); err != nil {
		return nil, err
	}
	return result, nil
}

type scoredProcessTask struct {
	Task               ProcessTaskResult
	BySlug             []ProcessSlugResult
	FalsePositives     []ProcessFalsePositive
	FalseNegatives     []ProcessFalseNegative
	SeverityMismatches []ProcessSeverityMismatch
	slugTP             map[string]int
	slugFP             map[string]int
	slugFN             map[string]int
}

func processScoreTask(id, tasksDir string, seed uint64, corePromptOverride string) (scoredProcessTask, error) {
	taskDir := filepath.Join(tasksDir, id)
	key, err := loadProcessorAnswerKey(filepath.Join(taskDir, "answer.yaml"))
	if err != nil {
		return scoredProcessTask{}, err
	}
	dataDir, err := os.MkdirTemp("", "deepsec-process-bench-"+id+"-")
	if err != nil {
		return scoredProcessTask{}, err
	}
	defer os.RemoveAll(dataDir)

	projectRoot := filepath.Join(taskDir, "source")
	if _, err := os.Stat(projectRoot); os.IsNotExist(err) {
		projectRoot = taskDir
	}
	dataRoot := core.DataRootFromPath(dataDir)
	if _, err := dataRoot.EnsureProject(id, projectRoot, ""); err != nil {
		return scoredProcessTask{}, err
	}
	records, err := loadFixtureRecords(id, filepath.Join(taskDir, "files"), dataRoot)
	if err != nil {
		return scoredProcessTask{}, err
	}
	backend, err := mockbackend.NewSeeded(filepath.Join(taskDir, "responses.jsonl"), seed)
	if err != nil {
		return scoredProcessTask{}, err
	}
	outcome, err := processor.Process(context.Background(), processor.ProcessOptions{
		ProjectID: id, ProjectRoot: projectRoot, DataRoot: dataRoot,
		Backend: backend, ProviderName: "mock-replay", BatchSize: 1, Concurrency: 1,
		CorePromptOverride: corePromptOverride,
	})
	if err != nil {
		return scoredProcessTask{}, err
	}
	if backend.Consumed() != backend.TotalResponses() {
		return scoredProcessTask{}, fmt.Errorf("%s: consumed %d of %d recorded responses", id, backend.Consumed(), backend.TotalResponses())
	}
	processed, err := dataRoot.LoadAllFileRecords(id)
	if err != nil {
		return scoredProcessTask{}, err
	}
	scored := scoreProcessedRecords(id, key, records, processed, outcome)
	if key.ExpectedRefusals != nil && scored.Task.RefusalCount > *key.ExpectedRefusals {
		return scoredProcessTask{}, fmt.Errorf("%s: refusal count %d exceeds expected_refusals %d", id, scored.Task.RefusalCount, *key.ExpectedRefusals)
	}
	if key.ExpectedFindingsMin != nil && scored.Task.ProducedFindings < *key.ExpectedFindingsMin {
		return scoredProcessTask{}, fmt.Errorf("%s: produced findings %d below expected_findings_min %d", id, scored.Task.ProducedFindings, *key.ExpectedFindingsMin)
	}
	return scored, nil
}

func loadFixtureRecords(projectID, dir string, root core.DataRoot) ([]*core.FileRecord, error) {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return nil, err
	}
	records := make([]*core.FileRecord, 0, len(entries))
	for _, e := range entries {
		if e.IsDir() || filepath.Ext(e.Name()) != ".json" {
			continue
		}
		body, err := os.ReadFile(filepath.Join(dir, e.Name()))
		if err != nil {
			return nil, err
		}
		var rec core.FileRecord
		if err := json.Unmarshal(body, &rec); err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		if err := core.AssertSafeFilePath(rec.FilePath); err != nil {
			return nil, fmt.Errorf("%s: %w", e.Name(), err)
		}
		if rec.Status != core.StatusPending {
			return nil, fmt.Errorf("%s: status must be pending", e.Name())
		}
		if len(rec.Candidates) == 0 {
			return nil, fmt.Errorf("%s: candidates is required", e.Name())
		}
		rec.ProjectID = projectID
		if err := root.WriteFileRecord(&rec); err != nil {
			return nil, err
		}
		copy := rec
		records = append(records, &copy)
	}
	if len(records) == 0 {
		return nil, fmt.Errorf("%s: no fixture file records found", dir)
	}
	sort.Slice(records, func(i, j int) bool { return records[i].FilePath < records[j].FilePath })
	return records, nil
}

func scoreProcessedRecords(id string, key *ProcessorAnswerKey, input, processed []*core.FileRecord, outcome *processor.ProcessOutcome) scoredProcessTask {
	candidates := candidatesByFile(input)
	responseIndex := responseIndexByFile(input)
	produced := flattenProducedFindings(processed)
	expected := expectedProcessorFindings(key)
	matchedAnswer := map[int]bool{}
	matchedProduced := map[int]bool{}
	task := scoredProcessTask{slugTP: map[string]int{}, slugFP: map[string]int{}, slugFN: map[string]int{}}

	for pi, pf := range produced {
		ai := matchingAnswerIndex(pf, expected, matchedAnswer)
		if ai < 0 {
			task.slugFP[pf.VulnSlug]++
			task.FalsePositives = append(task.FalsePositives, ProcessFalsePositive{
				TaskID: id, File: pf.File, Line: firstLine(pf.LineNumbers), Slug: pf.VulnSlug,
				ClosestAnswer: closestProcessorAnswer(pf, expected), Title: pf.Title,
			})
			continue
		}
		matchedProduced[pi] = true
		matchedAnswer[ai] = true
		answer := expected[ai]
		task.slugTP[pf.VulnSlug]++
		if pf.Severity != answer.Severity {
			task.SeverityMismatches = append(task.SeverityMismatches, ProcessSeverityMismatch{
				TaskID: id, ID: answer.ID, File: answer.File, Slug: pf.VulnSlug, Expected: answer.Severity, Actual: pf.Severity,
			})
		}
	}

	candidateBacked := 0
	for i, answer := range expected {
		if answerHasCandidate(answer, candidates[answer.File]) {
			candidateBacked++
		}
		if matchedAnswer[i] {
			continue
		}
		task.slugFN[answer.VulnSlugs[0]]++
		task.FalseNegatives = append(task.FalseNegatives, ProcessFalseNegative{
			TaskID: id, FindingID: answer.ID, File: answer.File, StartLine: answer.Location.StartLine,
			EndLine: answer.Location.EndLine, VulnSlugs: answer.VulnSlugs,
			Candidates: candidates[answer.File], ResponseIndex: responseIndex[answer.File],
		})
	}
	refusals := countRefusals(processed)
	matches := len(matchedProduced)
	candidateBackedMatches := countCandidateBackedMatches(expected, matchedAnswer, candidates)
	task.Task = ProcessTaskResult{
		TaskID: id, ProcessorPrecision: rate(matches, len(produced)),
		ProcessorRecallGivenCandidate: rate(candidateBackedMatches, candidateBacked),
		ProcessorRecall:               rate(len(matchedAnswer), len(expected)),
		SeverityAccuracy:              rate(matches-len(task.SeverityMismatches), matches),
		RefusalRate:                   rate(refusals, outcome.BatchesRun),
		ProducedFindings:              len(produced), MatchedFindings: matches,
		CandidateBackedFindings: candidateBacked, CandidateBackedMatched: candidateBackedMatches,
		ExpectedFindings:   len(expected),
		FalsePositiveCount: len(task.FalsePositives), FalseNegativeCount: len(task.FalseNegatives),
		RefusalCount: refusals, BatchCount: outcome.BatchesRun,
	}
	slugs := map[string]struct{}{}
	for s := range task.slugTP {
		slugs[s] = struct{}{}
	}
	for s := range task.slugFP {
		slugs[s] = struct{}{}
	}
	for s := range task.slugFN {
		slugs[s] = struct{}{}
	}
	for slug := range slugs {
		task.BySlug = append(task.BySlug, ProcessSlugResult{
			TaskID: id, Slug: slug, TruePositive: task.slugTP[slug], FalsePositive: task.slugFP[slug],
			FalseNegative: task.slugFN[slug], Precision: rate(task.slugTP[slug], task.slugTP[slug]+task.slugFP[slug]),
			Recall: rate(task.slugTP[slug], task.slugTP[slug]+task.slugFN[slug]),
		})
	}
	sort.Slice(task.BySlug, func(i, j int) bool { return task.BySlug[i].Slug < task.BySlug[j].Slug })
	return task
}

func loadProcessorAnswerKey(path string) (*ProcessorAnswerKey, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var key ProcessorAnswerKey
	if err := yaml.Unmarshal(body, &key); err != nil {
		return nil, err
	}
	if err := key.Validate(); err != nil {
		return nil, err
	}
	return &key, nil
}

func (k *ProcessorAnswerKey) Validate() error {
	if len(k.Findings) == 0 && k.ExpectedRefusals == nil && k.ExpectedFindingsMin == nil {
		return fmt.Errorf("findings or an expected_* guard is required")
	}
	seen := map[string]struct{}{}
	for i, f := range k.Findings {
		if f.ID == "" {
			return fmt.Errorf("findings[%d]: id is required", i)
		}
		if _, ok := seen[f.ID]; ok {
			return fmt.Errorf("findings[%d]: duplicate id %q", i, f.ID)
		}
		seen[f.ID] = struct{}{}
		if err := core.AssertSafeFilePath(f.File); err != nil {
			return fmt.Errorf("findings[%d]: %w", i, err)
		}
		if len(f.VulnSlugs) == 0 {
			return fmt.Errorf("findings[%d]: vulnSlugs is required", i)
		}
		if f.Location.StartLine < 1 || f.Location.EndLine < f.Location.StartLine {
			return fmt.Errorf("findings[%d]: invalid location range", i)
		}
		switch f.Severity {
		case core.SeverityCritical, core.SeverityHigh, core.SeverityMedium, core.SeverityLow:
		default:
			return fmt.Errorf("findings[%d]: unsupported severity %q", i, f.Severity)
		}
	}
	if k.ExpectedRefusals != nil && *k.ExpectedRefusals < 0 {
		return fmt.Errorf("expected_refusals must be non-negative")
	}
	if k.ExpectedFindingsMin != nil && *k.ExpectedFindingsMin < 0 {
		return fmt.Errorf("expected_findings_min must be non-negative")
	}
	return nil
}

func expectedProcessorFindings(key *ProcessorAnswerKey) []ProcessorAnswerFinding {
	out := make([]ProcessorAnswerFinding, 0, len(key.Findings))
	for _, f := range key.Findings {
		if f.Processor.MustReportFinding == nil || *f.Processor.MustReportFinding {
			out = append(out, f)
		}
	}
	return out
}

func candidatesByFile(records []*core.FileRecord) map[string][]core.CandidateMatch {
	out := map[string][]core.CandidateMatch{}
	for _, r := range records {
		out[r.FilePath] = append([]core.CandidateMatch(nil), r.Candidates...)
	}
	return out
}

func responseIndexByFile(records []*core.FileRecord) map[string]int {
	out := map[string]int{}
	sorted := append([]*core.FileRecord(nil), records...)
	sort.Slice(sorted, func(i, j int) bool { return sorted[i].FilePath < sorted[j].FilePath })
	for i, r := range sorted {
		out[r.FilePath] = i + 1
	}
	return out
}

func flattenProducedFindings(records []*core.FileRecord) []producedFindingRef {
	var out []producedFindingRef
	for _, r := range records {
		for _, f := range r.Findings {
			out = append(out, producedFindingRef{File: r.FilePath, Finding: f})
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

func matchingAnswerIndex(pf producedFindingRef, answers []ProcessorAnswerFinding, used map[int]bool) int {
	for i, answer := range answers {
		if used[i] || pf.File != answer.File || !SlugMatches(pf.VulnSlug, answer.VulnSlugs) {
			continue
		}
		for _, line := range pf.LineNumbers {
			if answer.Location.Contains(line) {
				return i
			}
		}
	}
	return -1
}

func answerHasCandidate(answer ProcessorAnswerFinding, candidates []core.CandidateMatch) bool {
	for _, c := range candidates {
		if !SlugMatches(c.VulnSlug, answer.VulnSlugs) {
			continue
		}
		for _, line := range c.LineNumbers {
			if answer.Location.Contains(line) {
				return true
			}
		}
	}
	return false
}

func countCandidateBackedMatches(answers []ProcessorAnswerFinding, matched map[int]bool, candidates map[string][]core.CandidateMatch) int {
	n := 0
	for i, answer := range answers {
		if matched[i] && answerHasCandidate(answer, candidates[answer.File]) {
			n++
		}
	}
	return n
}

func closestProcessorAnswer(pf producedFindingRef, answers []ProcessorAnswerFinding) string {
	best, label := math.MaxInt, ""
	for _, answer := range answers {
		if answer.File != pf.File {
			continue
		}
		dist := distanceToRange(firstLine(pf.LineNumbers), answer.Location)
		if dist < best {
			best = dist
			label = answer.ID
		}
	}
	return label
}

func countRefusals(records []*core.FileRecord) int {
	n := 0
	for _, r := range records {
		for _, e := range r.AnalysisHistory {
			if e.Refusal != nil && e.Refusal.Refused {
				n++
			}
		}
	}
	return n
}

type processAccumulator struct {
	produced, matched, expected, candidateBacked, candidateBackedMatched int
	severityOK, refusalCount, batchCount, fp, fn                         int
	slugTP, slugFP, slugFN                                               map[string]int
}

func (a *processAccumulator) add(t scoredProcessTask) {
	a.produced += t.Task.ProducedFindings
	a.matched += t.Task.MatchedFindings
	a.expected += t.Task.ExpectedFindings
	a.candidateBacked += t.Task.CandidateBackedFindings
	a.candidateBackedMatched += t.Task.CandidateBackedMatched
	a.severityOK += t.Task.MatchedFindings - len(t.SeverityMismatches)
	a.refusalCount += t.Task.RefusalCount
	a.batchCount += t.Task.BatchCount
	a.fp += t.Task.FalsePositiveCount
	a.fn += t.Task.FalseNegativeCount
	for slug, n := range t.slugTP {
		a.slugTP[slug] += n
	}
	for slug, n := range t.slugFP {
		a.slugFP[slug] += n
	}
	for slug, n := range t.slugFN {
		a.slugFN[slug] += n
	}
}

func (a processAccumulator) summary(ts, outDir string) ProcessSummary {
	precision := map[string]float64{}
	recall := map[string]float64{}
	slugs := map[string]struct{}{}
	for s := range a.slugTP {
		slugs[s] = struct{}{}
	}
	for s := range a.slugFP {
		slugs[s] = struct{}{}
	}
	for s := range a.slugFN {
		slugs[s] = struct{}{}
	}
	for slug := range slugs {
		precision[slug] = rate(a.slugTP[slug], a.slugTP[slug]+a.slugFP[slug])
		recall[slug] = rate(a.slugTP[slug], a.slugTP[slug]+a.slugFN[slug])
	}
	return ProcessSummary{
		GeneratedAt: ts, ProcessorPrecision: rate(a.matched, a.produced),
		ProcessorRecallGivenCandidate: rate(a.candidateBackedMatched, a.candidateBacked),
		ProcessorRecall:               rate(a.matched, a.expected), SeverityAccuracy: rate(a.severityOK, a.matched),
		RefusalRate: rate(a.refusalCount, a.batchCount), FalsePositiveCount: a.fp, FalseNegativeCount: a.fn,
		PerSlugPrecision: precision, PerSlugRecall: recall, OutputDir: outDir,
	}
}

func writeProcessReports(outDir string, result *ProcessRunResult) error {
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(outDir, "summary.json"), result.Summary); err != nil {
		return err
	}
	if err := writeTSV(filepath.Join(outDir, "by_task.tsv"), processTaskRows(result.Tasks)); err != nil {
		return err
	}
	if err := writeTSV(filepath.Join(outDir, "by_slug.tsv"), processSlugRows(result.BySlug)); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(outDir, "false_positives.json"), result.FalsePositives); err != nil {
		return err
	}
	if err := writeJSON(filepath.Join(outDir, "false_negatives.json"), result.FalseNegatives); err != nil {
		return err
	}
	return writeJSON(filepath.Join(outDir, "severity_mismatches.json"), result.SeverityMismatches)
}

func processTaskRows(tasks []ProcessTaskResult) [][]string {
	rows := [][]string{{"task_id", "processor_precision", "processor_recall_given_candidate", "processor_recall", "severity_accuracy", "refusal_rate", "produced_findings", "matched_findings", "false_positive_count", "false_negative_count"}}
	for _, t := range tasks {
		rows = append(rows, []string{t.TaskID, ftoa(t.ProcessorPrecision), ftoa(t.ProcessorRecallGivenCandidate), ftoa(t.ProcessorRecall), ftoa(t.SeverityAccuracy), ftoa(t.RefusalRate), itoa(t.ProducedFindings), itoa(t.MatchedFindings), itoa(t.FalsePositiveCount), itoa(t.FalseNegativeCount)})
	}
	return rows
}

func processSlugRows(slugs []ProcessSlugResult) [][]string {
	rows := [][]string{{"task_id", "slug", "true_positive", "false_positive", "false_negative", "precision", "recall"}}
	for _, s := range slugs {
		rows = append(rows, []string{s.TaskID, s.Slug, itoa(s.TruePositive), itoa(s.FalsePositive), itoa(s.FalseNegative), ftoa(s.Precision), ftoa(s.Recall)})
	}
	return rows
}

func (r ProcessRunResult) CanonicalReports() string {
	body, _ := json.Marshal(ProcessRunResult{
		Summary: ProcessSummary{
			TaskCount: r.Summary.TaskCount, ProcessorPrecision: r.Summary.ProcessorPrecision,
			ProcessorRecallGivenCandidate: r.Summary.ProcessorRecallGivenCandidate, ProcessorRecall: r.Summary.ProcessorRecall,
			SeverityAccuracy: r.Summary.SeverityAccuracy, RefusalRate: r.Summary.RefusalRate,
			FalsePositiveCount: r.Summary.FalsePositiveCount, FalseNegativeCount: r.Summary.FalseNegativeCount,
			PerSlugPrecision: r.Summary.PerSlugPrecision, PerSlugRecall: r.Summary.PerSlugRecall,
		},
		Tasks: r.Tasks, BySlug: r.BySlug, FalsePositives: r.FalsePositives,
		FalseNegatives: r.FalseNegatives, SeverityMismatches: r.SeverityMismatches,
	})
	return strings.TrimSpace(string(body))
}
