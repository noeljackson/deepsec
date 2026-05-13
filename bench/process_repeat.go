package bench

import (
	"encoding/json"
	"fmt"
	"math"
	"math/rand/v2"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

const defaultBootstrapSamples = 1000
const maxRepeatedSamplesInJSON = 100

type ProcessRepeatedResult struct {
	GeneratedAt      string                    `json:"generated_at"`
	Repeat           int                       `json:"repeat"`
	Seed             uint64                    `json:"seed"`
	BootstrapSamples int                       `json:"bootstrap_samples"`
	Metrics          map[string]RepeatedMetric `json:"metrics"`
	LastRun          *ProcessRunResult         `json:"-"`
}

type RepeatedMetric struct {
	Mean    float64   `json:"mean"`
	Stddev  float64   `json:"stddev"`
	Median  float64   `json:"median"`
	CILow   float64   `json:"ci_low"`
	CIHigh  float64   `json:"ci_high"`
	Samples []float64 `json:"samples"`
}

type ProcessCompareOptions struct {
	OutDir           string
	Threshold        float64
	Seed             uint64
	BootstrapSamples int
}

type ProcessCompareReport struct {
	GeneratedAt      string                 `json:"generated_at"`
	BaselineDir      string                 `json:"baseline_dir"`
	CandidateDir     string                 `json:"candidate_dir"`
	Threshold        float64                `json:"threshold"`
	Seed             uint64                 `json:"seed"`
	BootstrapSamples int                    `json:"bootstrap_samples"`
	Metrics          []ProcessCompareMetric `json:"metrics"`
	OutputDir        string                 `json:"output_dir"`
}

type ProcessCompareMetric struct {
	Name      string  `json:"name"`
	MeanA     float64 `json:"mean_a"`
	MeanB     float64 `json:"mean_b"`
	Diff      float64 `json:"diff"`
	CILow     float64 `json:"ci_low"`
	CIHigh    float64 `json:"ci_high"`
	Direction string  `json:"direction"`
	Verdict   string  `json:"verdict"`
}

func ProcessScoreRepeated(taskIDs []string, opts ProcessScoreOptions) (*ProcessRepeatedResult, error) {
	if opts.TasksDir == "" {
		opts.TasksDir = filepath.Join("bench", "processor-fixtures")
	}
	if opts.OutDir == "" {
		opts.OutDir = filepath.Join("bench", "out-processor")
	}
	if opts.Repeat < 1 {
		opts.Repeat = 1
	}
	if opts.BootstrapSamples == 0 {
		opts.BootstrapSamples = defaultBootstrapSamples
	}
	if opts.BootstrapSamples < defaultBootstrapSamples {
		return nil, fmt.Errorf("bootstrap samples must be at least %d", defaultBootstrapSamples)
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

	outDir := filepath.Join(opts.OutDir, now)
	samples := map[string][]float64{}
	var last *ProcessRunResult
	for i := 0; i < opts.Repeat; i++ {
		repeatOpts := opts
		repeatOpts.Now = fmt.Sprintf("%s/repeat-%03d", now, i+1)
		runDir := filepath.Join(outDir, fmt.Sprintf("repeat-%03d", i+1))
		run, err := processScoreOnce(taskIDs, repeatOpts, runDir, opts.Seed+uint64(i))
		if err != nil {
			return nil, err
		}
		last = run
		addProcessSummarySamples(samples, run.Summary)
	}

	result := &ProcessRepeatedResult{
		GeneratedAt:      now,
		Repeat:           opts.Repeat,
		Seed:             opts.Seed,
		BootstrapSamples: opts.BootstrapSamples,
		Metrics:          summarizeRepeatedMetrics(samples, opts.BootstrapSamples, opts.Seed),
		LastRun:          last,
	}
	if err := writeJSON(filepath.Join(outDir, "summary-repeated.json"), result); err != nil {
		return nil, err
	}
	return result, nil
}

func addProcessSummarySamples(samples map[string][]float64, s ProcessSummary) {
	samples["processor_precision"] = append(samples["processor_precision"], s.ProcessorPrecision)
	samples["processor_recall_given_candidate"] = append(samples["processor_recall_given_candidate"], s.ProcessorRecallGivenCandidate)
	samples["processor_recall"] = append(samples["processor_recall"], s.ProcessorRecall)
	samples["severity_accuracy"] = append(samples["severity_accuracy"], s.SeverityAccuracy)
	samples["refusal_rate"] = append(samples["refusal_rate"], s.RefusalRate)
	samples["false_positive_count"] = append(samples["false_positive_count"], float64(s.FalsePositiveCount))
	samples["false_negative_count"] = append(samples["false_negative_count"], float64(s.FalseNegativeCount))
	for slug, v := range s.PerSlugPrecision {
		samples["per_slug_precision:"+slug] = append(samples["per_slug_precision:"+slug], v)
	}
	for slug, v := range s.PerSlugRecall {
		samples["per_slug_recall:"+slug] = append(samples["per_slug_recall:"+slug], v)
	}
}

func summarizeRepeatedMetrics(samples map[string][]float64, bootstrapSamples int, seed uint64) map[string]RepeatedMetric {
	out := map[string]RepeatedMetric{}
	names := make([]string, 0, len(samples))
	for name := range samples {
		names = append(names, name)
	}
	sort.Strings(names)
	for i, name := range names {
		out[name] = summarizeRepeatedSample(samples[name], bootstrapSamples, seed+uint64(i)*9973)
	}
	return out
}

func summarizeRepeatedSample(values []float64, bootstrapSamples int, seed uint64) RepeatedMetric {
	copied := append([]float64(nil), values...)
	sort.Float64s(copied)
	ciLow, ciHigh := bootstrapMeanCI(values, bootstrapSamples, seed)
	return RepeatedMetric{
		Mean:    mean(values),
		Stddev:  stddev(values),
		Median:  medianSorted(copied),
		CILow:   ciLow,
		CIHigh:  ciHigh,
		Samples: cappedSamples(values),
	}
}

func cappedSamples(values []float64) []float64 {
	limit := len(values)
	if limit > maxRepeatedSamplesInJSON {
		limit = maxRepeatedSamplesInJSON
	}
	return append([]float64(nil), values[:limit]...)
}

func bootstrapMeanCI(values []float64, bootstrapSamples int, seed uint64) (float64, float64) {
	if len(values) == 0 {
		return 0, 0
	}
	if bootstrapSamples < 1 {
		bootstrapSamples = defaultBootstrapSamples
	}
	rng := rand.New(rand.NewPCG(seed, seed^0x243f6a8885a308d3))
	means := make([]float64, bootstrapSamples)
	for i := range means {
		sum := 0.0
		for range values {
			sum += values[rng.IntN(len(values))]
		}
		means[i] = sum / float64(len(values))
	}
	sort.Float64s(means)
	return percentileSorted(means, 0.025), percentileSorted(means, 0.975)
}

func ProcessCompare(aDir, bDir string, opts ProcessCompareOptions) (*ProcessCompareReport, error) {
	if opts.BootstrapSamples == 0 {
		opts.BootstrapSamples = defaultBootstrapSamples
	}
	if opts.BootstrapSamples < defaultBootstrapSamples {
		return nil, fmt.Errorf("bootstrap samples must be at least %d", defaultBootstrapSamples)
	}
	a, err := loadRepeatedSummary(filepath.Join(aDir, "summary-repeated.json"))
	if err != nil {
		return nil, err
	}
	b, err := loadRepeatedSummary(filepath.Join(bDir, "summary-repeated.json"))
	if err != nil {
		return nil, err
	}
	outDir := opts.OutDir
	if outDir == "" {
		outDir = bDir
	}
	report := &ProcessCompareReport{
		GeneratedAt:      time.Now().UTC().Format("20060102T150405Z"),
		BaselineDir:      aDir,
		CandidateDir:     bDir,
		Threshold:        opts.Threshold,
		Seed:             opts.Seed,
		BootstrapSamples: opts.BootstrapSamples,
		OutputDir:        outDir,
	}
	names := commonMetricNames(a.Metrics, b.Metrics)
	for i, name := range names {
		am := a.Metrics[name]
		bm := b.Metrics[name]
		low, high := bootstrapDiffCI(am.Samples, bm.Samples, opts.BootstrapSamples, opts.Seed+uint64(i)*7919)
		diff := bm.Mean - am.Mean
		direction := metricDirection(name)
		report.Metrics = append(report.Metrics, ProcessCompareMetric{
			Name:      name,
			MeanA:     am.Mean,
			MeanB:     bm.Mean,
			Diff:      diff,
			CILow:     low,
			CIHigh:    high,
			Direction: direction,
			Verdict:   compareVerdict(low, high, opts.Threshold, direction),
		})
	}
	if err := os.MkdirAll(outDir, 0o755); err != nil {
		return nil, err
	}
	if err := writeJSON(filepath.Join(outDir, "process-compare.json"), report); err != nil {
		return nil, err
	}
	if err := writeTSV(filepath.Join(outDir, "process-compare.tsv"), processCompareRows(report.Metrics)); err != nil {
		return nil, err
	}
	return report, nil
}

func loadRepeatedSummary(path string) (*ProcessRepeatedResult, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var out ProcessRepeatedResult
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, err
	}
	if len(out.Metrics) == 0 {
		return nil, fmt.Errorf("%s: no repeated metrics found", path)
	}
	return &out, nil
}

func commonMetricNames(a, b map[string]RepeatedMetric) []string {
	var out []string
	for name := range a {
		if _, ok := b[name]; ok {
			out = append(out, name)
		}
	}
	sort.Strings(out)
	return out
}

func bootstrapDiffCI(a, b []float64, bootstrapSamples int, seed uint64) (float64, float64) {
	if len(a) == 0 || len(b) == 0 {
		return 0, 0
	}
	rng := rand.New(rand.NewPCG(seed, seed^0x13198a2e03707344))
	diffs := make([]float64, bootstrapSamples)
	for i := range diffs {
		diffs[i] = bootstrapMeanWithRNG(b, rng) - bootstrapMeanWithRNG(a, rng)
	}
	sort.Float64s(diffs)
	return percentileSorted(diffs, 0.025), percentileSorted(diffs, 0.975)
}

func bootstrapMeanWithRNG(values []float64, rng *rand.Rand) float64 {
	sum := 0.0
	for range values {
		sum += values[rng.IntN(len(values))]
	}
	return sum / float64(len(values))
}

func compareVerdict(low, high, threshold float64, direction string) string {
	switch direction {
	case "lower":
		if high < -threshold {
			return "improved"
		}
		if low > threshold {
			return "regressed"
		}
	default:
		if low > threshold {
			return "improved"
		}
		if high < -threshold {
			return "regressed"
		}
	}
	return "inconclusive"
}

func metricDirection(name string) string {
	switch name {
	case "false_positive_count", "false_negative_count", "refusal_rate":
		return "lower"
	default:
		return "higher"
	}
}

func processCompareRows(metrics []ProcessCompareMetric) [][]string {
	rows := [][]string{{"metric", "mean_a", "mean_b", "diff", "ci_low", "ci_high", "direction", "verdict"}}
	for _, m := range metrics {
		rows = append(rows, []string{m.Name, ftoa(m.MeanA), ftoa(m.MeanB), ftoa(m.Diff), ftoa(m.CILow), ftoa(m.CIHigh), m.Direction, m.Verdict})
	}
	return rows
}

func mean(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	sum := 0.0
	for _, v := range values {
		sum += v
	}
	return sum / float64(len(values))
}

func stddev(values []float64) float64 {
	if len(values) < 2 {
		return 0
	}
	m := mean(values)
	sum := 0.0
	for _, v := range values {
		d := v - m
		sum += d * d
	}
	return math.Sqrt(sum / float64(len(values)-1))
}

func medianSorted(values []float64) float64 {
	if len(values) == 0 {
		return 0
	}
	mid := len(values) / 2
	if len(values)%2 == 1 {
		return values[mid]
	}
	return (values[mid-1] + values[mid]) / 2
}

func percentileSorted(values []float64, p float64) float64 {
	if len(values) == 0 {
		return 0
	}
	idx := int(math.Round(p * float64(len(values)-1)))
	if idx < 0 {
		idx = 0
	}
	if idx >= len(values) {
		idx = len(values) - 1
	}
	return values[idx]
}

func ProcessCompareTSV(report *ProcessCompareReport) string {
	rows := processCompareRows(report.Metrics)
	var b strings.Builder
	for _, row := range rows {
		b.WriteString(strings.Join(row, "\t"))
		b.WriteByte('\n')
	}
	return b.String()
}
