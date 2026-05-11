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

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn parses_minimal_config() {
        let body = r#"
default_agent = "openai"

[[projects]]
id = "p"
root = "."
"#;
        let cfg: DeepsecConfig = toml::from_str(body).unwrap();
        assert_eq!(cfg.default_agent.as_deref(), Some("openai"));
        assert_eq!(cfg.projects.len(), 1);
        assert_eq!(cfg.find_project("p").unwrap().root, ".");
        assert!(cfg.find_project("nonexistent").is_none());
    }

    #[test]
    fn parses_full_config() {
        let body = r#"
default_agent = "anthropic"
data_dir = "my-data"

[matchers]
only = ["a", "b"]
exclude = ["c"]
extra_paths = ["./x.toml"]

[[projects]]
id = "first"
root = "./apps/first"
github_url = "https://github.com/o/r/blob/main"
info_markdown = """
ctx
"""
prompt_append = "be careful"
priority_paths = ["src/", "lib/"]

[[projects]]
id = "second"
root = "/abs/path"
"#;
        let cfg: DeepsecConfig = toml::from_str(body).unwrap();
        assert_eq!(cfg.data_dir.as_deref(), Some("my-data"));
        assert_eq!(cfg.matchers.only, vec!["a", "b"]);
        assert_eq!(cfg.matchers.exclude, vec!["c"]);
        assert_eq!(cfg.matchers.extra_paths, vec!["./x.toml"]);
        assert_eq!(cfg.projects.len(), 2);
        let p = cfg.find_project("first").unwrap();
        assert_eq!(
            p.github_url.as_deref(),
            Some("https://github.com/o/r/blob/main")
        );
        assert_eq!(p.priority_paths, vec!["src/", "lib/"]);
        assert!(p.info_markdown.as_deref().unwrap().contains("ctx"));
    }

    #[test]
    fn rejects_unknown_fields() {
        let body = r#"
default_agent = "openai"
totally_not_a_field = "x"

[[projects]]
id = "p"
root = "."
"#;
        // deny_unknown_fields is set on DeepsecConfig.
        let r: Result<DeepsecConfig, _> = toml::from_str(body);
        assert!(r.is_err());
    }

    #[test]
    fn no_projects_returns_error() {
        let dir = tempdir().unwrap();
        let p = dir.path().join("deepsec.config.toml");
        fs_err::write(&p, "default_agent = \"anthropic\"\n").unwrap();
        let r = load_config(&p);
        assert!(matches!(r, Err(ConfigError::NoProjects)));
    }

    #[test]
    fn find_config_file_walks_up_from_subdir() {
        let dir = tempdir().unwrap();
        let cfg_path = dir.path().join("deepsec.config.toml");
        fs_err::write(&cfg_path, "[[projects]]\nid = \"x\"\nroot = \".\"\n").unwrap();
        let nested = dir.path().join("a").join("b").join("c");
        fs_err::create_dir_all(&nested).unwrap();
        let found = find_config_file(&nested).expect("walked up");
        assert_eq!(found, cfg_path);
    }

    #[test]
    fn find_config_file_returns_none_when_absent() {
        let dir = tempdir().unwrap();
        let r = find_config_file(dir.path());
        assert!(r.is_none());
    }

    #[test]
    fn find_config_file_finds_dot_deepsec_variant() {
        let dir = tempdir().unwrap();
        let inner = dir.path().join(".deepsec");
        fs_err::create_dir_all(&inner).unwrap();
        let cfg_path = inner.join("config.toml");
        fs_err::write(&cfg_path, "[[projects]]\nid = \"x\"\nroot = \".\"\n").unwrap();
        let found = find_config_file(dir.path()).expect("found via .deepsec/");
        assert_eq!(found, cfg_path);
    }
}
