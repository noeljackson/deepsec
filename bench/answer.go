package bench

import (
	"fmt"
	"os"

	"github.com/noeljackson/deepsec/internal/core"
	"gopkg.in/yaml.v3"
)

const DefaultTolerance = 3

type AnswerKey struct {
	Issues []Issue `yaml:"issues"`
	Decoys []Decoy `yaml:"decoys"`
}

type Issue struct {
	ID        string             `yaml:"id"`
	File      string             `yaml:"file"`
	Severity  core.Severity      `yaml:"severity"`
	CWE       string             `yaml:"cwe,omitempty"`
	VulnSlugs []string           `yaml:"vulnSlugs"`
	Location  Location           `yaml:"location"`
	Scanner   ScannerExpectation `yaml:"scanner"`
}

type Location struct {
	StartLine int  `yaml:"startLine"`
	EndLine   int  `yaml:"endLine"`
	Tolerance *int `yaml:"tolerance,omitempty"`
}

type ScannerExpectation struct {
	MustEmitCandidate bool   `yaml:"mustEmitCandidate"`
	Reason            string `yaml:"reason,omitempty"`
}

type Decoy struct {
	ID             string   `yaml:"id"`
	File           string   `yaml:"file"`
	Line           int      `yaml:"line"`
	ForbiddenSlugs []string `yaml:"forbiddenSlugs"`
}

func LoadAnswerKey(path string) (*AnswerKey, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	var key AnswerKey
	if err := yaml.Unmarshal(body, &key); err != nil {
		return nil, err
	}
	if err := key.Validate(); err != nil {
		return nil, err
	}
	return &key, nil
}

func (k *AnswerKey) Validate() error {
	seen := map[string]struct{}{}
	for i, issue := range k.Issues {
		if issue.ID == "" {
			return fmt.Errorf("issues[%d]: id is required", i)
		}
		if _, ok := seen[issue.ID]; ok {
			return fmt.Errorf("issues[%d]: duplicate id %q", i, issue.ID)
		}
		seen[issue.ID] = struct{}{}
		if err := core.AssertSafeFilePath(issue.File); err != nil {
			return fmt.Errorf("issues[%d]: %w", i, err)
		}
		if len(issue.VulnSlugs) == 0 {
			return fmt.Errorf("issues[%d]: vulnSlugs is required", i)
		}
		if issue.Location.StartLine < 1 || issue.Location.EndLine < issue.Location.StartLine {
			return fmt.Errorf("issues[%d]: invalid location range", i)
		}
		if issue.Location.Tolerance != nil && *issue.Location.Tolerance < 0 {
			return fmt.Errorf("issues[%d]: tolerance must be non-negative", i)
		}
		switch issue.Severity {
		case core.SeverityCritical, core.SeverityHigh, core.SeverityMedium, core.SeverityLow:
		default:
			return fmt.Errorf("issues[%d]: unsupported severity %q", i, issue.Severity)
		}
	}
	for i, decoy := range k.Decoys {
		if decoy.ID == "" {
			return fmt.Errorf("decoys[%d]: id is required", i)
		}
		if err := core.AssertSafeFilePath(decoy.File); err != nil {
			return fmt.Errorf("decoys[%d]: %w", i, err)
		}
		if decoy.Line < 1 {
			return fmt.Errorf("decoys[%d]: line must be positive", i)
		}
		if len(decoy.ForbiddenSlugs) == 0 {
			return fmt.Errorf("decoys[%d]: forbiddenSlugs is required", i)
		}
	}
	return nil
}

func (l Location) ToleranceOrDefault() int {
	if l.Tolerance == nil {
		return DefaultTolerance
	}
	return *l.Tolerance
}

func (l Location) Contains(line int) bool {
	tol := l.ToleranceOrDefault()
	return line >= l.StartLine-tol && line <= l.EndLine+tol
}

func SlugMatches(slug string, aliases []string) bool {
	for _, alias := range aliases {
		if slug == alias {
			return true
		}
	}
	return false
}
