// Package prompts loads the embedded prompt profile used by the processor.
package prompts

import (
	"fmt"
	"io/fs"
	"sort"
	"strings"

	"github.com/BurntSushi/toml"
)

const (
	corePromptFile     = "core.md"
	agentPromptFile    = "agent.md"
	patcherPromptFile  = "patcher.md"
	frameworkHintsFile = "framework_hints.toml"
	slugHintsFile      = "slug_hints.toml"
)

var bundledProfile = mustLoad(promptFiles)

// Profile is the parsed embedded prompt data.
type Profile struct {
	CorePrompt     string
	FrameworkHints map[string]string
	CandidateNotes map[string]string
}

type frameworkHintsDoc struct {
	Highlights []frameworkHint `toml:"highlight"`
}

type frameworkHint struct {
	Tag  string `toml:"tag"`
	Text string `toml:"text"`
}

type slugHintsDoc struct {
	Notes []slugNote `toml:"note"`
}

type slugNote struct {
	Slug string `toml:"slug"`
	Text string `toml:"text"`
}

func mustLoad(fsys fs.FS) *Profile {
	p, err := Load(fsys)
	if err != nil {
		panic(err)
	}
	return p
}

// Load parses a prompt profile from fsys. It is exported for tests and future
// profile-selection work; production code uses the embedded profile above.
func Load(fsys fs.FS) (*Profile, error) {
	core, err := fs.ReadFile(fsys, corePromptFile)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", corePromptFile, err)
	}
	if strings.TrimSpace(string(core)) == "" {
		return nil, fmt.Errorf("%s: empty core prompt", corePromptFile)
	}
	frameworks, err := loadFrameworkHints(fsys)
	if err != nil {
		return nil, err
	}
	notes, err := loadSlugHints(fsys)
	if err != nil {
		return nil, err
	}
	return &Profile{
		CorePrompt:     string(core),
		FrameworkHints: frameworks,
		CandidateNotes: notes,
	}, nil
}

// CorePrompt returns the shared system-prompt preamble.
func CorePrompt() string {
	return bundledProfile.CorePrompt
}

// AgentPrompt returns the bounded matcher-patch proposer prompt.
func AgentPrompt() string {
	body, err := fs.ReadFile(promptFiles, agentPromptFile)
	if err != nil {
		panic(err)
	}
	return string(body)
}

// PatcherPrompt returns the finding-to-source-patch proposer prompt.
func PatcherPrompt() string {
	body, err := fs.ReadFile(promptFiles, patcherPromptFile)
	if err != nil {
		panic(err)
	}
	return string(body)
}

// HighlightForTag returns framework-specific threat context for a detected
// tech tag, or empty string for unknown tags.
func HighlightForTag(tag string) string {
	return bundledProfile.FrameworkHints[tag]
}

// NoteForSlug returns the per-matcher reasoning hint, or empty string.
func NoteForSlug(slug string) string {
	return bundledProfile.CandidateNotes[slug]
}

// FrameworkTags returns the embedded framework hint keys in stable order.
func FrameworkTags() []string {
	return sortedKeys(bundledProfile.FrameworkHints)
}

// Slugs returns the embedded candidate-note keys in stable order.
func Slugs() []string {
	return sortedKeys(bundledProfile.CandidateNotes)
}

func loadFrameworkHints(fsys fs.FS) (map[string]string, error) {
	body, err := fs.ReadFile(fsys, frameworkHintsFile)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", frameworkHintsFile, err)
	}
	var doc frameworkHintsDoc
	if err := decodeStrict(frameworkHintsFile, body, &doc); err != nil {
		return nil, err
	}
	out := make(map[string]string, len(doc.Highlights))
	for i, h := range doc.Highlights {
		if strings.TrimSpace(h.Tag) == "" {
			return nil, fmt.Errorf("%s: highlight[%d]: empty tag", frameworkHintsFile, i)
		}
		if strings.TrimSpace(h.Text) == "" {
			return nil, fmt.Errorf("%s: highlight[%d]: empty text", frameworkHintsFile, i)
		}
		if _, exists := out[h.Tag]; exists {
			return nil, fmt.Errorf("%s: duplicate tag %q", frameworkHintsFile, h.Tag)
		}
		out[h.Tag] = h.Text
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s: no highlights", frameworkHintsFile)
	}
	return out, nil
}

func loadSlugHints(fsys fs.FS) (map[string]string, error) {
	body, err := fs.ReadFile(fsys, slugHintsFile)
	if err != nil {
		return nil, fmt.Errorf("%s: %w", slugHintsFile, err)
	}
	var doc slugHintsDoc
	if err := decodeStrict(slugHintsFile, body, &doc); err != nil {
		return nil, err
	}
	out := make(map[string]string, len(doc.Notes))
	for i, n := range doc.Notes {
		if strings.TrimSpace(n.Slug) == "" {
			return nil, fmt.Errorf("%s: note[%d]: empty slug", slugHintsFile, i)
		}
		if strings.TrimSpace(n.Text) == "" {
			return nil, fmt.Errorf("%s: note[%d]: empty text", slugHintsFile, i)
		}
		if _, exists := out[n.Slug]; exists {
			return nil, fmt.Errorf("%s: duplicate slug %q", slugHintsFile, n.Slug)
		}
		out[n.Slug] = n.Text
	}
	if len(out) == 0 {
		return nil, fmt.Errorf("%s: no notes", slugHintsFile)
	}
	return out, nil
}

func decodeStrict(name string, body []byte, v any) error {
	meta, err := toml.Decode(string(body), v)
	if err != nil {
		return fmt.Errorf("%s: %w", name, err)
	}
	if undecoded := meta.Undecoded(); len(undecoded) > 0 {
		return fmt.Errorf("%s: unknown keys: %v", name, undecoded)
	}
	return nil
}

func sortedKeys(m map[string]string) []string {
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}
