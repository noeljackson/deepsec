package prompts

import (
	"embed"
	"io/fs"
)

//go:embed core.md framework_hints.toml slug_hints.toml agent.md patcher.md
var promptFiles embed.FS

// BundledPromptFS exposes the embedded prompt files so callers outside
// this package can hash the bundled prompt pack for provenance.
func BundledPromptFS() fs.FS { return promptFiles }
