use deepsec_core::CandidateMatch;
use fancy_regex::Regex;
use serde::{Deserialize, Serialize};
use std::path::Path;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum MatcherError {
    #[error("io error: {0}")]
    Io(#[from] std::io::Error),
    #[error("toml error: {0}")]
    Toml(#[from] toml::de::Error),
    #[error("invalid regex for matcher {slug}: {source}")]
    Regex {
        slug: String,
        #[source]
        source: fancy_regex::Error,
    },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "lowercase")]
pub enum NoiseTier {
    Precise,
    #[default]
    Normal,
    Noisy,
}

impl NoiseTier {
    pub fn rank(self) -> u32 {
        match self {
            NoiseTier::Precise => 0,
            NoiseTier::Normal => 1,
            NoiseTier::Noisy => 2,
        }
    }
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct MatcherGate {
    #[serde(default)]
    pub tech: Vec<String>,
    #[serde(default, rename = "sentinel_files")]
    pub sentinel_files: Vec<String>,
    #[serde(default, rename = "sentinel_contains")]
    pub sentinel_contains: Vec<String>,
}

/// Declarative matcher definition (TOML wire form).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct MatcherDef {
    pub slug: String,
    pub description: String,
    #[serde(default)]
    pub noise_tier: NoiseTier,
    pub file_patterns: Vec<String>,
    /// One or more regex patterns. A hit on any one produces a match.
    pub patterns: Vec<String>,
    /// Optional regex that, if matched within the window, suppresses
    /// the hit (used to skip lines containing a guard like "maxSteps:").
    #[serde(default)]
    pub suppress_patterns: Vec<String>,
    /// Optional file-content prerequisite. The matcher is short-circuited
    /// to no-op unless ALL of these regexes match somewhere in the file
    /// (used for "skip unless this file imports the AI SDK", etc.).
    #[serde(default)]
    pub require_content: Vec<String>,
    /// Optional file-path regex blacklist (e.g. `\.test\.ts$`).
    #[serde(default)]
    pub exclude_path_patterns: Vec<String>,
    /// Snippet window — lines BEFORE the match included in the snippet.
    #[serde(default = "default_before")]
    pub snippet_before: usize,
    /// Snippet window — lines AFTER the match included in the snippet.
    #[serde(default = "default_after")]
    pub snippet_after: usize,
    /// Matcher's prompt label, used in `matchedPattern`.
    #[serde(default)]
    pub label: Option<String>,
    #[serde(default)]
    pub requires: MatcherGate,
}

fn default_before() -> usize {
    1
}
fn default_after() -> usize {
    5
}

#[derive(Debug)]
pub struct Matcher {
    pub def: MatcherDef,
    patterns: Vec<Regex>,
    suppress: Vec<Regex>,
    require: Vec<Regex>,
    exclude_paths: Vec<Regex>,
}

impl Matcher {
    pub fn slug(&self) -> &str {
        &self.def.slug
    }

    pub fn file_patterns(&self) -> &[String] {
        &self.def.file_patterns
    }

    pub fn requires(&self) -> &MatcherGate {
        &self.def.requires
    }

    pub fn noise_tier(&self) -> NoiseTier {
        self.def.noise_tier
    }

    pub fn description(&self) -> &str {
        &self.def.description
    }

    pub fn matches(&self, content: &str, file_path: &str) -> Vec<CandidateMatch> {
        for ex in &self.exclude_paths {
            if ex.is_match(file_path).unwrap_or(false) {
                return Vec::new();
            }
        }
        for req in &self.require {
            if !req.is_match(content).unwrap_or(false) {
                return Vec::new();
            }
        }

        let lines: Vec<&str> = content.split('\n').collect();
        let mut out = Vec::new();
        for pat in &self.patterns {
            let mut start = 0;
            while let Ok(Some(m)) = pat.find_from_pos(content, start) {
                let m_start = m.start();
                let m_end = m.end().max(m_start + 1);
                // line number — 1-based
                let line_no = content[..m_start].bytes().filter(|b| *b == b'\n').count() + 1;
                let snippet = build_snippet(
                    &lines,
                    line_no,
                    self.def.snippet_before,
                    self.def.snippet_after,
                );
                let suppress = self
                    .suppress
                    .iter()
                    .any(|s| s.is_match(&snippet).unwrap_or(false));
                if !suppress {
                    out.push(CandidateMatch {
                        vuln_slug: self.def.slug.clone(),
                        line_numbers: vec![line_no],
                        snippet,
                        matched_pattern: self
                            .def
                            .label
                            .clone()
                            .unwrap_or_else(|| pat.as_str().to_string()),
                    });
                }
                start = m_end;
            }
        }
        dedup_matches(&mut out);
        out
    }
}

fn build_snippet(lines: &[&str], line_no: usize, before: usize, after: usize) -> String {
    let start = line_no.saturating_sub(before + 1);
    let end = (line_no + after).min(lines.len());
    lines[start..end].join("\n")
}

fn dedup_matches(matches: &mut Vec<CandidateMatch>) {
    let mut seen = std::collections::HashSet::new();
    matches.retain(|m| {
        let key = format!("{}|{}|{:?}", m.vuln_slug, m.matched_pattern, m.line_numbers);
        seen.insert(key)
    });
}

pub fn compile(def: MatcherDef) -> Result<Matcher, MatcherError> {
    let patterns = def
        .patterns
        .iter()
        .map(|p| {
            Regex::new(p).map_err(|e| MatcherError::Regex {
                slug: def.slug.clone(),
                source: e,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let suppress = def
        .suppress_patterns
        .iter()
        .map(|p| {
            Regex::new(p).map_err(|e| MatcherError::Regex {
                slug: def.slug.clone(),
                source: e,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let require = def
        .require_content
        .iter()
        .map(|p| {
            Regex::new(p).map_err(|e| MatcherError::Regex {
                slug: def.slug.clone(),
                source: e,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    let exclude_paths = def
        .exclude_path_patterns
        .iter()
        .map(|p| {
            Regex::new(p).map_err(|e| MatcherError::Regex {
                slug: def.slug.clone(),
                source: e,
            })
        })
        .collect::<Result<Vec<_>, _>>()?;
    Ok(Matcher {
        def,
        patterns,
        suppress,
        require,
        exclude_paths,
    })
}

#[derive(Debug, Deserialize)]
struct MatcherFile {
    #[serde(default, rename = "matcher")]
    matchers: Vec<MatcherDef>,
}

pub fn parse_matcher_toml(body: &str) -> Result<Vec<Matcher>, MatcherError> {
    let file: MatcherFile = toml::from_str(body)?;
    file.matchers.into_iter().map(compile).collect()
}

pub fn load_matcher_toml(path: &Path) -> Result<Vec<Matcher>, MatcherError> {
    let body = fs_err::read_to_string(path)?;
    parse_matcher_toml(&body)
}

pub fn load_matchers_from_dir(dir: &Path) -> Result<Vec<Matcher>, MatcherError> {
    let mut out = Vec::new();
    if !dir.is_dir() {
        return Ok(out);
    }
    for entry in fs_err::read_dir(dir)? {
        let entry = entry?;
        let path = entry.path();
        if path.extension().and_then(|e| e.to_str()) == Some("toml") {
            out.extend(load_matcher_toml(&path)?);
        }
    }
    Ok(out)
}

/// Embedded bundled matcher pack. Each entry is `(filename, contents)`.
/// The CLI loads these before any user-specified extras.
pub const BUILTIN_MATCHERS: &[(&str, &str)] = &[
    ("core.toml", include_str!("../matchers/core.toml")),
    ("secrets.toml", include_str!("../matchers/secrets.toml")),
    ("crypto.toml", include_str!("../matchers/crypto.toml")),
    ("nextjs.toml", include_str!("../matchers/nextjs.toml")),
    ("express.toml", include_str!("../matchers/express.toml")),
    ("python.toml", include_str!("../matchers/python.toml")),
    ("rails.toml", include_str!("../matchers/rails.toml")),
    ("go.toml", include_str!("../matchers/go.toml")),
    ("rust.toml", include_str!("../matchers/rust.toml")),
    ("infra.toml", include_str!("../matchers/infra.toml")),
    ("ai.toml", include_str!("../matchers/ai.toml")),
    ("extras.toml", include_str!("../matchers/extras.toml")),
];

pub fn load_builtin() -> Result<Vec<Matcher>, MatcherError> {
    let mut out = Vec::new();
    for (name, body) in BUILTIN_MATCHERS {
        let parsed = parse_matcher_toml(body).map_err(|e| match e {
            MatcherError::Toml(te) => MatcherError::Regex {
                slug: format!("file:{name}"),
                source: fancy_regex::Error::ParseError(
                    0,
                    fancy_regex::ParseError::GeneralParseError(format!("{te}")),
                ),
            },
            other => other,
        })?;
        out.extend(parsed);
    }
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn builtin_matchers_parse() {
        let m = load_builtin().expect("builtin matchers should compile");
        assert!(m.len() >= 30, "got {} matchers", m.len());
    }

    #[test]
    fn simple_match_works() {
        let body = r#"
[[matcher]]
slug = "test"
description = "t"
file_patterns = ["**/*.ts"]
patterns = ["\\bDEBUG\\s*=\\s*True\\b"]
label = "debug true"
"#;
        let ms = parse_matcher_toml(body).unwrap();
        let hits = ms[0].matches("x = 1\nDEBUG = True\n", "foo.ts");
        assert_eq!(hits.len(), 1);
        assert_eq!(hits[0].line_numbers, vec![2]);
    }
}
