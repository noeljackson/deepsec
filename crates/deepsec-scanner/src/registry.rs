use crate::matchers::{Matcher, MatcherError, NoiseTier, load_builtin};
use indexmap::IndexMap;

#[derive(Debug, Default)]
pub struct MatcherRegistry {
    matchers: IndexMap<String, Matcher>,
}

impl MatcherRegistry {
    pub fn new() -> Self {
        Self::default()
    }

    pub fn with_builtin() -> Result<Self, MatcherError> {
        let mut reg = Self::new();
        for m in load_builtin()? {
            reg.register(m);
        }
        Ok(reg)
    }

    pub fn register(&mut self, m: Matcher) {
        let slug = m.slug().to_string();
        self.matchers.insert(slug, m);
    }

    pub fn extend(&mut self, ms: impl IntoIterator<Item = Matcher>) {
        for m in ms {
            self.register(m);
        }
    }

    pub fn get(&self, slug: &str) -> Option<&Matcher> {
        self.matchers.get(slug)
    }

    pub fn iter(&self) -> impl Iterator<Item = &Matcher> {
        self.matchers.values()
    }

    pub fn len(&self) -> usize {
        self.matchers.len()
    }

    pub fn is_empty(&self) -> bool {
        self.matchers.is_empty()
    }

    pub fn slugs(&self) -> Vec<String> {
        self.matchers.keys().cloned().collect()
    }

    pub fn noise_tier(&self, slug: &str) -> NoiseTier {
        self.matchers
            .get(slug)
            .map(|m| m.noise_tier())
            .unwrap_or(NoiseTier::Normal)
    }

    /// Apply `--only` / `--exclude` filter (post-registration). Removes
    /// matchers in `exclude`; if `only` is non-empty, keeps only those.
    pub fn apply_filter(&mut self, only: &[String], exclude: &[String]) {
        let only_set: std::collections::HashSet<&str> =
            only.iter().map(String::as_str).collect();
        let excl_set: std::collections::HashSet<&str> =
            exclude.iter().map(String::as_str).collect();
        self.matchers.retain(|slug, _| {
            if excl_set.contains(slug.as_str()) {
                return false;
            }
            if only_set.is_empty() {
                return true;
            }
            only_set.contains(slug.as_str())
        });
    }
}
