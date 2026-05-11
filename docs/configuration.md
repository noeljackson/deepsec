# Configuration reference

`deepsec` reads `deepsec.config.toml` from the current working directory,
walking up. Alternate names also accepted: `.deepsec/config.toml` and
`deepsec.toml`. Pass `--config <path>` to override the search.

## Top-level

```toml
# Default AI backend when --agent is not passed.
default_agent = "anthropic"          # or "openai"

# Override the on-disk data root. Default: "data". Relative paths are
# resolved against the directory containing this config file.
# data_dir = "data"

[matchers]
# Whitelist of matcher slugs to run. Empty = run everything bundled.
only = []
# Blacklist of matcher slugs.
exclude = []
# Extra matcher TOML files (paths relative to this config).
extra_paths = []
```

## Projects

At least one `[[projects]]` entry is required.

```toml
[[projects]]
id            = "myproj"             # used by --project-id
root          = "."                  # absolute, or relative to this config
github_url    = "https://github.com/acme/repo/blob/main"

# Inline prompt context surfaced to the agent. Optional.
info_markdown = """
This service handles payments. Tenants are identified by `org_id` in JWT.
"""

# Appended verbatim to the system prompt.
prompt_append = "Pay extra attention to /api/admin/*."

# Files under these prefixes are investigated first.
priority_paths = ["src/api/admin/", "src/lib/auth/"]
```

## Environment variables

| Variable              | Used by                  | Purpose                              |
|-----------------------|--------------------------|--------------------------------------|
| `ANTHROPIC_API_KEY`   | `--agent anthropic`      | Bearer key for Anthropic API         |
| `ANTHROPIC_BASE_URL`  | `--agent anthropic`      | Override (default `api.anthropic.com`) |
| `OPENAI_API_KEY`      | `--agent openai`         | Bearer key for OpenAI API            |
| `OPENAI_BASE_URL`     | `--agent openai`         | Override (Azure, OpenRouter, vLLM, …) |
| `DEEPSEC_DATA_ROOT`   | all                      | Override `data/` mirror location     |
| `DEEPSEC_CONFIG`      | all                      | Override config file lookup          |

Validate everything resolves with `deepsec preflight`.
