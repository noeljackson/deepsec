package regressions

import (
	"fmt"
	"os"

	"github.com/BurntSushi/toml"
	"github.com/noeljackson/deepsec/internal/core"
)

const (
	MustFire    = "must_fire"
	MustNotFire = "must_not_fire"
)

type Case struct {
	Slug        string `toml:"slug"`
	Expectation string `toml:"expectation"`
	Content     string `toml:"content"`
	FilePath    string `toml:"file_path"`
	Reason      string `toml:"reason"`
	SourceRef   string `toml:"source_ref,omitempty"`
	AddedAt     string `toml:"added_at"`
}

type Corpus struct {
	Cases []Case `toml:"case"`
}

func Load(path string) (Corpus, error) {
	body, err := os.ReadFile(path)
	if err != nil {
		return Corpus{}, err
	}
	var corpus Corpus
	if err := toml.Unmarshal(body, &corpus); err != nil {
		return Corpus{}, fmt.Errorf("parse regression cases %s: %w", path, err)
	}
	for i, c := range corpus.Cases {
		if c.Slug == "" {
			return Corpus{}, fmt.Errorf("regression case %d: slug is required", i)
		}
		if c.Expectation != MustFire && c.Expectation != MustNotFire {
			return Corpus{}, fmt.Errorf("regression case %d: expectation must be %q or %q", i, MustFire, MustNotFire)
		}
		if c.Content == "" {
			return Corpus{}, fmt.Errorf("regression case %d: content is required", i)
		}
		if err := core.AssertSafeFilePath(c.FilePath); err != nil {
			return Corpus{}, fmt.Errorf("regression case %d: %w", i, err)
		}
	}
	return corpus, nil
}
