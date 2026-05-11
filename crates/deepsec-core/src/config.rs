use serde::{Deserialize, Serialize};
use std::path::{Path, PathBuf};
use thiserror::Error;

#[derive(Debug, Error)]
pub enum ConfigError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("toml parse error: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("config has no projects[]")]
    NoProjects,
}

/// Top-level `deepsec.config.toml` shape.
///
/// TOML replaces the legacy `deepsec.config.ts`. Plugins are no longer
/// JavaScript modules; custom matcher TOML files can be listed under
/// `matchers.extra_paths` and behave like the bundled matchers.
#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct DeepsecConfig {
    #[serde(default)]
    pub projects: Vec<ProjectDeclaration>,
    /// Override on-disk data root. Defaults to `data/`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub data_dir: Option<String>,
    /// Default agent backend used by `deepsec process` when no
    /// `--agent` flag is supplied. One of `claude` | `openai`.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub default_agent: Option<String>,
    #[serde(default)]
    pub matchers: MatcherFilter,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct MatcherFilter {
    /// Whitelist: only run these slugs. Empty = run everything.
    #[serde(default)]
    pub only: Vec<String>,
    /// Blacklist: never run these slugs.
    #[serde(default)]
    pub exclude: Vec<String>,
    /// Additional TOML matcher files to load on top of the bundled
    /// matcher pack. Paths are relative to the config file.
    #[serde(default)]
    pub extra_paths: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(deny_unknown_fields)]
pub struct ProjectDeclaration {
    pub id: String,
    /// Project root. Absolute, or relative to the config file.
    pub root: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub github_url: Option<String>,
    /// Inline prompt context (replaces the legacy INFO.md file).
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub info_markdown: Option<String>,
    /// Appended verbatim to the agent prompt.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_append: Option<String>,
    /// Files under these prefixes are investigated first.
    #[serde(default)]
    pub priority_paths: Vec<String>,
}

const CONFIG_FILES: &[&str] = &[
    "deepsec.config.toml",
    ".deepsec/config.toml",
    "deepsec.toml",
];

/// Walk upward from `start` looking for a `deepsec.config.toml`.
pub fn find_config_file(start: &Path) -> Option<PathBuf> {
    let mut cur = Some(start.to_path_buf());
    while let Some(dir) = cur {
        for name in CONFIG_FILES {
            let candidate = dir.join(name);
            if candidate.is_file() {
                return Some(candidate);
            }
        }
        cur = dir.parent().map(Path::to_path_buf);
    }
    None
}

pub fn load_config(path: &Path) -> Result<DeepsecConfig, ConfigError> {
    let body = fs_err::read_to_string(path)?;
    let cfg: DeepsecConfig = toml::from_str(&body)?;
    if cfg.projects.is_empty() {
        return Err(ConfigError::NoProjects);
    }
    Ok(cfg)
}

impl DeepsecConfig {
    pub fn find_project(&self, id: &str) -> Option<&ProjectDeclaration> {
        self.projects.iter().find(|p| p.id == id)
    }
}
