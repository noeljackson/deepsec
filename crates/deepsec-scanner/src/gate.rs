use crate::detect::DetectedTech;
use crate::matchers::MatcherGate;
use globset::{Glob, GlobSetBuilder};
use std::collections::HashSet;
use std::path::Path;

/// Evaluate a matcher's `requires` gate. Returns true when the matcher
/// should run. Semantics mirror the TS implementation:
///   - empty gate → always runs.
///   - `tech` set → at least one tag must be in `detected.tags`.
///   - `sentinel_files` set → at least one path/glob must exist under
///     `root`. When `sentinel_contains` is set, the file content must
///     also match at least one of those regexes.
///   - Both present → EITHER passing is enough (union, not intersection).
pub fn evaluate_gate(gate: &MatcherGate, detected: &DetectedTech, root: &Path) -> bool {
    if gate.tech.is_empty() && gate.sentinel_files.is_empty() {
        return true;
    }
    if !gate.tech.is_empty() {
        let have: HashSet<&str> = detected.tags.iter().map(String::as_str).collect();
        if gate.tech.iter().any(|t| have.contains(t.as_str())) {
            return true;
        }
    }
    if !gate.sentinel_files.is_empty() {
        if has_sentinel(&gate.sentinel_files, &gate.sentinel_contains, root) {
            return true;
        }
    }
    false
}

fn has_sentinel(patterns: &[String], contains: &[String], root: &Path) -> bool {
    let mut builder = GlobSetBuilder::new();
    let mut any = false;
    for p in patterns {
        if !p.contains('*') {
            // literal path
            if root.join(p).exists() {
                if contains.is_empty() {
                    return true;
                }
                if let Ok(body) = fs_err::read_to_string(root.join(p)) {
                    if contains_any(&body, contains) {
                        return true;
                    }
                }
            }
            continue;
        }
        if let Ok(g) = Glob::new(p) {
            builder.add(g);
            any = true;
        }
    }
    if !any {
        return false;
    }
    let Ok(set) = builder.build() else {
        return false;
    };

    for entry in walkdir::WalkDir::new(root)
        .max_depth(8)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        if !entry.file_type().is_file() {
            continue;
        }
        let rel = match entry.path().strip_prefix(root) {
            Ok(p) => p,
            Err(_) => continue,
        };
        if set.is_match(rel) {
            if contains.is_empty() {
                return true;
            }
            if let Ok(body) = fs_err::read_to_string(entry.path()) {
                if contains_any(&body, contains) {
                    return true;
                }
            }
        }
    }
    false
}

fn contains_any(body: &str, patterns: &[String]) -> bool {
    for p in patterns {
        if let Ok(re) = fancy_regex::Regex::new(p) {
            if re.is_match(body).unwrap_or(false) {
                return true;
            }
        }
    }
    false
}
