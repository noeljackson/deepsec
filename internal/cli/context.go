// Package cli wires the cobra command tree.
package cli

import (
	"fmt"
	"os"
	"path/filepath"

	"github.com/noeljackson/deepsec/internal/core"
	"github.com/noeljackson/deepsec/internal/processor/providers"
)

// Context is shared state passed to every command.
type Context struct {
	Config     *core.DeepsecConfig
	ConfigPath string
	DataRoot   core.DataRoot
	CWD        string
	Providers  *providers.Registry
}

// LoadContext discovers a deepsec.config.toml, loads providers, and
// resolves the data root.
func LoadContext(configFlag, dataDirFlag string) (*Context, error) {
	cwd, err := os.Getwd()
	if err != nil {
		return nil, err
	}

	configPath := configFlag
	if configPath == "" {
		configPath = core.FindConfigFile(cwd)
	}

	var cfg *core.DeepsecConfig
	if configPath != "" {
		cfg, err = core.LoadConfig(configPath)
		if err != nil {
			return nil, fmt.Errorf("loading %s: %w", configPath, err)
		}
	}

	dataRoot := resolveDataRoot(dataDirFlag, cfg, configPath, cwd)

	reg, err := providers.LoadBuiltin()
	if err != nil {
		return nil, err
	}
	if cfg != nil && len(cfg.Providers) > 0 {
		if err := reg.MergeUserConfig(cfg.Providers); err != nil {
			return nil, err
		}
	}

	return &Context{
		Config:     cfg,
		ConfigPath: configPath,
		DataRoot:   dataRoot,
		CWD:        cwd,
		Providers:  reg,
	}, nil
}

func resolveDataRoot(flagOverride string, cfg *core.DeepsecConfig, configPath, cwd string) core.DataRoot {
	if flagOverride != "" {
		return core.DataRootFromPath(flagOverride)
	}
	if cfg != nil && cfg.DataDir != "" {
		base := cwd
		if configPath != "" {
			base = filepath.Dir(configPath)
		}
		return core.DataRootFromPath(filepath.Join(base, cfg.DataDir))
	}
	return core.DataRootFromEnv()
}

// ResolvedProject is a project entry with its root path made absolute.
type ResolvedProject struct {
	Decl core.ProjectDeclaration
	Root string
}

// Project resolves a project id to its declaration + absolute root.
func (ctx *Context) Project(id string) (*ResolvedProject, error) {
	if ctx.Config == nil {
		return nil, fmt.Errorf("no deepsec.config.toml found; run `deepsec init`")
	}
	p := ctx.Config.FindProject(id)
	if p == nil {
		return nil, fmt.Errorf("project %q not in config", id)
	}
	base := ctx.CWD
	if ctx.ConfigPath != "" {
		base = filepath.Dir(ctx.ConfigPath)
	}
	root := p.Root
	if !filepath.IsAbs(root) {
		root = filepath.Join(base, root)
	}
	return &ResolvedProject{Decl: *p, Root: root}, nil
}

// ResolveAgent picks a provider name. Preference order:
//
//	explicit flag → config.default_agent → "anthropic"
func (ctx *Context) ResolveAgent(flag string) string {
	if flag != "" {
		return flag
	}
	if ctx.Config != nil && ctx.Config.DefaultAgent != "" {
		return ctx.Config.DefaultAgent
	}
	return "anthropic"
}
