package scanner

import (
	"embed"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"strings"

	"github.com/BurntSushi/toml"
)

//go:embed matchers/*.toml
var bundledMatchers embed.FS

// MatcherFile is the on-disk TOML container. One file may declare any
// number of `[[matcher]]` entries.
type MatcherFile struct {
	Matchers []MatcherDef `toml:"matcher"`
}

// Registry holds the active set of matchers, keyed by slug.
type Registry struct {
	matchers map[string]*Matcher
	order    []string
	hasAST   bool
}

func NewRegistry() *Registry {
	return &Registry{matchers: map[string]*Matcher{}}
}

// WithBuiltin returns a Registry populated with every TOML file
// embedded under matchers/*.toml. The bundled pack is compiled at
// init time so a broken matcher fails fast.
func WithBuiltin() (*Registry, error) {
	r := NewRegistry()
	entries, err := bundledMatchers.ReadDir("matchers")
	if err != nil {
		return nil, err
	}
	for _, e := range entries {
		if e.IsDir() || !strings.HasSuffix(e.Name(), ".toml") {
			continue
		}
		body, err := bundledMatchers.ReadFile(filepath.Join("matchers", e.Name()))
		if err != nil {
			return nil, err
		}
		if err := r.LoadTOMLBytes(body, e.Name()); err != nil {
			return nil, err
		}
	}
	return r, nil
}

// LoadTOMLBytes decodes one TOML matcher file and registers each entry.
func (r *Registry) LoadTOMLBytes(body []byte, source string) error {
	var f MatcherFile
	if err := toml.Unmarshal(body, &f); err != nil {
		return fmt.Errorf("%s: %w", source, err)
	}
	for _, d := range f.Matchers {
		m, err := Compile(d)
		if err != nil {
			return fmt.Errorf("%s: %w", source, err)
		}
		r.Register(m)
	}
	return nil
}

// LoadTOMLFile reads a TOML matcher file from disk.
func (r *Registry) LoadTOMLFile(path string) error {
	body, err := os.ReadFile(path)
	if err != nil {
		return err
	}
	return r.LoadTOMLBytes(body, path)
}

// LoadTOMLDir loads every *.toml file under dir.
func (r *Registry) LoadTOMLDir(dir string) error {
	return filepath.WalkDir(dir, func(p string, d fs.DirEntry, err error) error {
		if err != nil {
			return err
		}
		if !d.IsDir() && strings.HasSuffix(p, ".toml") {
			return r.LoadTOMLFile(p)
		}
		return nil
	})
}

// Register adds m to the registry, overwriting any prior entry with
// the same slug. Order of first registration is preserved for stable
// `list-matchers` output.
func (r *Registry) Register(m *Matcher) {
	if _, ok := r.matchers[m.Slug()]; !ok {
		r.order = append(r.order, m.Slug())
	}
	r.matchers[m.Slug()] = m
	r.refreshHasAST()
}

func (r *Registry) Get(slug string) *Matcher { return r.matchers[slug] }
func (r *Registry) Len() int                 { return len(r.matchers) }

// All returns matchers in registration order.
func (r *Registry) All() []*Matcher {
	out := make([]*Matcher, 0, len(r.matchers))
	for _, slug := range r.order {
		if m, ok := r.matchers[slug]; ok {
			out = append(out, m)
		}
	}
	return out
}

// Slugs returns the registered slugs in registration order.
func (r *Registry) Slugs() []string {
	return append([]string(nil), r.order...)
}

// NoiseTier returns the tier for the given slug, defaulting to Normal.
func (r *Registry) NoiseTier(slug string) NoiseTier {
	if m, ok := r.matchers[slug]; ok {
		return m.NoiseTier()
	}
	return NoiseNormal
}

// ApplyFilter drops matchers in `exclude`; if `only` is non-empty, keeps
// only those listed there.
func (r *Registry) ApplyFilter(only, exclude []string) {
	onlySet := toSet(only)
	exclSet := toSet(exclude)
	kept := map[string]*Matcher{}
	keptOrder := make([]string, 0, len(r.order))
	for _, slug := range r.order {
		m := r.matchers[slug]
		if _, drop := exclSet[slug]; drop {
			continue
		}
		if len(onlySet) > 0 {
			if _, keep := onlySet[slug]; !keep {
				continue
			}
		}
		kept[slug] = m
		keptOrder = append(keptOrder, slug)
	}
	r.matchers = kept
	r.order = keptOrder
	r.refreshHasAST()
}

func toSet(xs []string) map[string]struct{} {
	out := map[string]struct{}{}
	for _, x := range xs {
		out[x] = struct{}{}
	}
	return out
}

func (r *Registry) HasASTPatterns() bool { return r.hasAST }

func (r *Registry) refreshHasAST() {
	r.hasAST = false
	for _, m := range r.matchers {
		if m.HasASTPatterns() {
			r.hasAST = true
			return
		}
	}
}
