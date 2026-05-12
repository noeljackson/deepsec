# Configuration reference

`deepsec` reads `deepsec.config.toml` from the current working directory,
walking up. Alternate names also accepted: `.deepsec/config.toml` and
`deepsec.toml`. Pass `--config <path>` to override.

## Top-level

```toml
# Default AI provider when --agent is not passed.
default_agent = "anthropic"

# Override the on-disk data root (default: "data"). Relative paths are
# resolved against the config file's directory.
# data_dir = "data"

[matchers]
only = []           # whitelist of matcher slugs
exclude = []        # blacklist
extra_paths = []    # additional matcher TOML files
```

## Projects

At least one `[[projects]]` entry is required.

```toml
[[projects]]
id            = "myproj"
root          = "."                     # absolute, or relative to this config
github_url    = "https://github.com/acme/repo/blob/main"

info_markdown = """
Inline prompt context surfaced to the agent.
"""
prompt_append = "Pay extra attention to /api/admin/*."
priority_paths = ["src/api/admin/", "src/lib/auth/"]
```

## Providers

Six providers ship built-in: `anthropic`, `openai`, `glm`, `kimi`,
`deepseek`, `openrouter`. Add a custom one by defining
`[providers.<name>]` in your config:

```toml
[providers.my-azure]
kind = "openai-compatible"           # or "anthropic"
base_url = "https://my-resource.openai.azure.com/openai/deployments/gpt-4"
api_key_env = "AZURE_OPENAI_KEY"
default_model = "gpt-4"
headers = { "api-version" = "2024-08-01-preview" }

[providers.my-azure.caps]
tool_use = true                      # function-calling reliability
prompt_cache = "auto"                # none | auto | explicit | moonshot-context
structured_output = "json_schema"    # json_schema | json_object | json_in_text

[[providers.my-azure.pricing]]
model = "gpt-4"
input_per_mtok_usd = 30.0
output_per_mtok_usd = 60.0
```

User-defined providers replace built-ins of the same name.

### Capability flags

| Field               | Meaning |
|---------------------|---------|
| `tool_use`          | `true` if the provider implements OpenAI-style function calls reliably. When `true`, deepsec registers a `report_findings` tool the model invokes for structured output. |
| `prompt_cache`      | `none` (default) / `auto` (provider caches automatically) / `explicit` (Anthropic-style `cache_control`) / `moonshot-context` (Moonshot's separate context-cache API). |
| `structured_output` | `json_schema` (strict-schema enforced) / `json_object` (JSON mode, no schema) / `json_in_text` (free text; deepsec parses JSON-in-text as fallback). |

## Environment variables

| Variable              | Used by                  | Purpose                              |
|-----------------------|--------------------------|--------------------------------------|
| `ANTHROPIC_API_KEY`   | `--agent anthropic`      | Anthropic API key                    |
| `ANTHROPIC_BASE_URL`  | `--agent anthropic`      | Override (default: SDK default)      |
| `OPENAI_API_KEY`      | `--agent openai`         | OpenAI API key                       |
| `OPENAI_BASE_URL`     | `--agent openai`         | Override (Azure / proxy / local)     |
| `GLM_API_KEY`         | `--agent glm`            | Zhipu GLM key                        |
| `MOONSHOT_API_KEY`    | `--agent kimi`           | Moonshot key                         |
| `DEEPSEEK_API_KEY`    | `--agent deepseek`       | DeepSeek key                         |
| `OPENROUTER_API_KEY`  | `--agent openrouter`     | OpenRouter key                       |
| `DEEPSEC_DATA_ROOT`   | all                      | Override `data/` mirror location     |
| `DEEPSEC_CONFIG`      | all                      | Override config file lookup          |

Validate via `deepsec preflight --agent <name>`.
