package prompts

import "embed"

//go:embed core.md framework_hints.toml slug_hints.toml agent.md
var promptFiles embed.FS
