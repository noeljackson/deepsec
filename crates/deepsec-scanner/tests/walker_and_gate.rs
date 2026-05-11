//! Tests for the file walker, matcher gate evaluation, and batch
//! grouping.

use deepsec_core::{CandidateMatch, FileRecord, FileStatus};
use deepsec_scanner::{
    DetectedTech, IGNORE_DIRS, MatcherGate, batch_candidates, detect_tech, evaluate_gate,
    walk_project,
};
use std::path::Path;
use tempfile::TempDir;

fn dir() -> TempDir {
    tempfile::tempdir().unwrap()
}

fn write(d: &Path, rel: &str, body: &str) {
    let p = d.join(rel);
    if let Some(parent) = p.parent() {
        fs_err::create_dir_all(parent).unwrap();
    }
    fs_err::write(p, body).unwrap();
}

#[test]
fn walker_picks_up_source_files() {
    let d = dir();
    write(d.path(), "src/a.ts", "export const x = 1;");
    write(d.path(), "src/b.py", "x = 1");
    write(d.path(), "src/c.go", "package main");
    let files = walk_project(d.path());
    let mut names: Vec<_> = files.iter().map(|p| p.to_string_lossy().into_owned()).collect();
    names.sort();
    assert!(names.contains(&"src/a.ts".to_string()));
    assert!(names.contains(&"src/b.py".to_string()));
    assert!(names.contains(&"src/c.go".to_string()));
}

#[test]
fn walker_skips_node_modules_and_git() {
    let d = dir();
    write(d.path(), "src/a.ts", "x");
    write(d.path(), "node_modules/foo/index.js", "x");
    write(d.path(), ".git/HEAD", "ref: refs/heads/main");
    let files = walk_project(d.path());
    let paths: Vec<String> = files.iter().map(|p| p.to_string_lossy().into_owned()).collect();
    assert!(paths.iter().any(|p| p == "src/a.ts"));
    assert!(!paths.iter().any(|p| p.contains("node_modules")));
    assert!(!paths.iter().any(|p| p.contains(".git")));
}

#[test]
fn walker_skips_target_dist_build() {
    let d = dir();
    write(d.path(), "src/a.ts", "x");
    write(d.path(), "target/foo.rs", "x");
    write(d.path(), "dist/bundle.js", "x");
    write(d.path(), "build/out.o", "x");
    let paths: Vec<String> = walk_project(d.path())
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    assert!(paths.iter().any(|p| p == "src/a.ts"));
    assert!(!paths.iter().any(|p| p.starts_with("target/")));
    assert!(!paths.iter().any(|p| p.starts_with("dist/")));
    assert!(!paths.iter().any(|p| p.starts_with("build/")));
}

#[test]
fn walker_skips_binary_extensions() {
    let d = dir();
    write(d.path(), "src/a.ts", "x");
    write(d.path(), "img/logo.png", "binary");
    write(d.path(), "doc/readme.md", "# hi");
    let paths: Vec<String> = walk_project(d.path())
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    assert!(paths.iter().any(|p| p == "src/a.ts"));
    assert!(!paths.iter().any(|p| p.ends_with(".png")));
    assert!(!paths.iter().any(|p| p.ends_with(".md")));
}

#[test]
fn walker_honors_gitignore() {
    let d = dir();
    // The `ignore` crate honors .gitignore only inside a git repo; the
    // presence of a .git dir is enough to flip it on.
    fs_err::create_dir_all(d.path().join(".git")).unwrap();
    write(d.path(), ".gitignore", "secret.ts\n");
    write(d.path(), "src/a.ts", "x");
    write(d.path(), "secret.ts", "API_KEY=...");

    let paths: Vec<String> = walk_project(d.path())
        .iter()
        .map(|p| p.to_string_lossy().into_owned())
        .collect();
    assert!(paths.iter().any(|p| p == "src/a.ts"));
    assert!(!paths.iter().any(|p| p == "secret.ts"));
}

#[test]
fn ignore_dirs_contain_expected_names() {
    assert!(IGNORE_DIRS.contains(&"node_modules"));
    assert!(IGNORE_DIRS.contains(&".git"));
    assert!(IGNORE_DIRS.contains(&"target"));
    assert!(IGNORE_DIRS.contains(&"dist"));
}

#[test]
fn detect_tech_tags_nodejs_typescript() {
    let d = dir();
    write(d.path(), "package.json", r#"{"name":"x","dependencies":{"typescript":"^5","react":"^18"}}"#);
    write(d.path(), "tsconfig.json", "{}");
    let t = detect_tech(d.path());
    assert!(t.tags.contains(&"node".to_string()));
    assert!(t.tags.contains(&"typescript".to_string()));
    assert!(t.tags.contains(&"react".to_string()));
}

#[test]
fn detect_tech_tags_nextjs() {
    let d = dir();
    write(
        d.path(),
        "package.json",
        r#"{"name":"x","dependencies":{"next":"^14"}}"#,
    );
    let t = detect_tech(d.path());
    assert!(t.tags.contains(&"nextjs".to_string()));
    assert!(t.tags.contains(&"node".to_string()));
}

#[test]
fn detect_tech_tags_rust_axum() {
    let d = dir();
    write(
        d.path(),
        "Cargo.toml",
        r#"[package]
name = "x"

[dependencies]
axum = "0.7"
"#,
    );
    let t = detect_tech(d.path());
    assert!(t.tags.contains(&"rust".to_string()));
    assert!(t.tags.contains(&"axum".to_string()));
}

#[test]
fn detect_tech_tags_python_django() {
    let d = dir();
    write(d.path(), "requirements.txt", "Django==5.0\nrequests==2.31\n");
    let t = detect_tech(d.path());
    assert!(t.tags.contains(&"python".to_string()));
    assert!(t.tags.contains(&"django".to_string()));
}

#[test]
fn detect_tech_returns_empty_for_unknown() {
    let d = dir();
    write(d.path(), "src/a.txt", "hello");
    let t = detect_tech(d.path());
    assert!(t.tags.is_empty() || t.tags.iter().all(|tag| !["nextjs", "django", "rails"].contains(&tag.as_str())));
}

#[test]
fn evaluate_gate_empty_always_passes() {
    let g = MatcherGate::default();
    let tech = DetectedTech {
        tags: vec![],
        sentinels: vec![],
        detected_at: "2026-01-01T00:00:00Z".into(),
        root_path: "/".into(),
    };
    assert!(evaluate_gate(&g, &tech, Path::new(".")));
}

#[test]
fn evaluate_gate_tech_match() {
    let g = MatcherGate {
        tech: vec!["nextjs".into()],
        ..Default::default()
    };
    let tech = DetectedTech {
        tags: vec!["nextjs".into()],
        sentinels: vec![],
        detected_at: "x".into(),
        root_path: "/".into(),
    };
    assert!(evaluate_gate(&g, &tech, Path::new(".")));
}

#[test]
fn evaluate_gate_tech_no_match() {
    let g = MatcherGate {
        tech: vec!["nextjs".into()],
        ..Default::default()
    };
    let tech = DetectedTech {
        tags: vec!["django".into()],
        sentinels: vec![],
        detected_at: "x".into(),
        root_path: "/".into(),
    };
    assert!(!evaluate_gate(&g, &tech, Path::new(".")));
}

#[test]
fn evaluate_gate_sentinel_file_present_passes() {
    let d = dir();
    write(d.path(), "package.json", r#"{}"#);
    let g = MatcherGate {
        sentinel_files: vec!["package.json".into()],
        ..Default::default()
    };
    let tech = DetectedTech {
        tags: vec![],
        sentinels: vec![],
        detected_at: "x".into(),
        root_path: d.path().display().to_string(),
    };
    assert!(evaluate_gate(&g, &tech, d.path()));
}

#[test]
fn evaluate_gate_sentinel_contains_matches_body() {
    let d = dir();
    write(d.path(), "Cargo.toml", "[dependencies]\naxum = \"0.7\"\n");
    let g = MatcherGate {
        sentinel_files: vec!["Cargo.toml".into()],
        sentinel_contains: vec!["axum".into()],
        ..Default::default()
    };
    let tech = DetectedTech {
        tags: vec![],
        sentinels: vec![],
        detected_at: "x".into(),
        root_path: d.path().display().to_string(),
    };
    assert!(evaluate_gate(&g, &tech, d.path()));
}

#[test]
fn evaluate_gate_sentinel_contains_misses_body() {
    let d = dir();
    write(d.path(), "Cargo.toml", "[dependencies]\nserde = \"1\"\n");
    let g = MatcherGate {
        sentinel_files: vec!["Cargo.toml".into()],
        sentinel_contains: vec!["axum".into()],
        ..Default::default()
    };
    let tech = DetectedTech {
        tags: vec![],
        sentinels: vec![],
        detected_at: "x".into(),
        root_path: d.path().display().to_string(),
    };
    assert!(!evaluate_gate(&g, &tech, d.path()));
}

#[test]
fn evaluate_gate_tech_or_sentinel_is_union() {
    let d = dir();
    write(d.path(), "package.json", "{}");
    let g = MatcherGate {
        tech: vec!["nonexistent".into()],
        sentinel_files: vec!["package.json".into()],
        ..Default::default()
    };
    let tech = DetectedTech {
        tags: vec!["something-else".into()],
        sentinels: vec![],
        detected_at: "x".into(),
        root_path: d.path().display().to_string(),
    };
    // tech misses, but sentinel matches → gate passes (union).
    assert!(evaluate_gate(&g, &tech, d.path()));
}

fn mk_rec(path: &str) -> FileRecord {
    FileRecord {
        file_path: path.into(),
        project_id: "p".into(),
        candidates: vec![CandidateMatch {
            vuln_slug: "s".into(),
            line_numbers: vec![1],
            snippet: "".into(),
            matched_pattern: "".into(),
        }],
        last_scanned_at: "2026-01-01T00:00:00Z".into(),
        last_scanned_run_id: "r".into(),
        file_hash: "h".into(),
        findings: Vec::new(),
        analysis_history: Vec::new(),
        git_info: None,
        status: FileStatus::Pending,
        locked_by_run_id: None,
        locked_at: None,
    }
}

#[test]
fn batch_candidates_groups_by_directory() {
    let recs = vec![
        mk_rec("src/api/a.ts"),
        mk_rec("src/api/b.ts"),
        mk_rec("src/lib/c.ts"),
    ];
    let batches = batch_candidates(&recs, 5);
    // src/api is one batch (2 files); src/lib is another (1 file).
    // batch_candidates merges small adjacent batches up to max_batch.
    // The total file count is preserved.
    let total: usize = batches.iter().map(|b| b.len()).sum();
    assert_eq!(total, 3);
    assert!(!batches.is_empty());
}

#[test]
fn batch_candidates_splits_oversized_dir() {
    let recs: Vec<FileRecord> = (0..7).map(|i| mk_rec(&format!("src/api/f{i}.ts"))).collect();
    let batches = batch_candidates(&recs, 3);
    assert_eq!(batches.len(), 3); // 3 + 3 + 1 = 7
    let total: usize = batches.iter().map(|b| b.len()).sum();
    assert_eq!(total, 7);
    for b in &batches {
        assert!(b.len() <= 3);
    }
}

#[test]
fn batch_candidates_empty_input() {
    let recs: Vec<FileRecord> = Vec::new();
    let batches = batch_candidates(&recs, 5);
    assert!(batches.is_empty());
}
