//! Persistence layer tests: project init, file records, runs.

use deepsec_core::{
    CandidateMatch, DataRoot, FileRecord, FileStatus, RunPhase, RunType, complete_run,
    create_run_meta, ensure_project, file_record_path, load_all_file_records, read_file_record,
    read_project_config, runs::list_runs, write_file_record, write_run_meta,
};
use tempfile::TempDir;

fn env() -> (TempDir, DataRoot) {
    let dir = tempfile::tempdir().unwrap();
    let root = DataRoot::from_path(dir.path().join("data"));
    (dir, root)
}

#[test]
fn ensure_project_is_idempotent() {
    let (_d, root) = env();
    let a = ensure_project(&root, "p", "/tmp/x", Some("https://github.com/x/r")).unwrap();
    let b = ensure_project(&root, "p", "/tmp/x", None).unwrap();
    // Idempotent: second call returns the SAME ProjectConfig (same createdAt).
    assert_eq!(a.project_id, b.project_id);
    assert_eq!(a.root_path, b.root_path);
    assert_eq!(a.created_at, b.created_at);
    assert_eq!(a.github_url, Some("https://github.com/x/r".into()));
}

#[test]
fn read_project_config_missing_returns_none() {
    let (_d, root) = env();
    assert!(read_project_config(&root, "missing").unwrap().is_none());
}

#[test]
fn file_record_roundtrip() {
    let (_d, root) = env();
    ensure_project(&root, "p", "/tmp/x", None).unwrap();
    let rec = FileRecord {
        file_path: "src/a.ts".into(),
        project_id: "p".into(),
        candidates: vec![CandidateMatch {
            vuln_slug: "s".into(),
            line_numbers: vec![1],
            snippet: "x".into(),
            matched_pattern: "p".into(),
        }],
        last_scanned_at: "2026-05-11T00:00:00Z".into(),
        last_scanned_run_id: "r".into(),
        file_hash: "h".into(),
        findings: Vec::new(),
        analysis_history: Vec::new(),
        git_info: None,
        status: FileStatus::Pending,
        locked_by_run_id: None,
        locked_at: None,
    };
    write_file_record(&root, &rec).unwrap();
    let back = read_file_record(&root, "p", "src/a.ts").unwrap().unwrap();
    assert_eq!(back.file_path, "src/a.ts");
    assert_eq!(back.candidates.len(), 1);
}

#[test]
fn read_file_record_missing_returns_none() {
    let (_d, root) = env();
    ensure_project(&root, "p", "/tmp/x", None).unwrap();
    assert!(read_file_record(&root, "p", "nope.ts").unwrap().is_none());
}

#[test]
fn load_all_file_records_walks_nested_dirs() {
    let (_d, root) = env();
    ensure_project(&root, "p", "/tmp/x", None).unwrap();
    for path in ["a.ts", "src/b.ts", "src/lib/c.ts"] {
        let rec = FileRecord {
            file_path: path.into(),
            project_id: "p".into(),
            candidates: Vec::new(),
            last_scanned_at: "2026-05-11T00:00:00Z".into(),
            last_scanned_run_id: "r".into(),
            file_hash: "h".into(),
            findings: Vec::new(),
            analysis_history: Vec::new(),
            git_info: None,
            status: FileStatus::Pending,
            locked_by_run_id: None,
            locked_at: None,
        };
        write_file_record(&root, &rec).unwrap();
    }
    let mut all = load_all_file_records(&root, "p").unwrap();
    all.sort_by_key(|r| r.file_path.clone());
    let paths: Vec<_> = all.iter().map(|r| r.file_path.as_str()).collect();
    assert_eq!(paths, vec!["a.ts", "src/b.ts", "src/lib/c.ts"]);
}

#[test]
fn load_all_file_records_empty_project_returns_empty() {
    let (_d, root) = env();
    ensure_project(&root, "p", "/tmp/x", None).unwrap();
    let all = load_all_file_records(&root, "p").unwrap();
    assert!(all.is_empty());
}

#[test]
fn run_meta_lifecycle() {
    let (_d, root) = env();
    ensure_project(&root, "p", "/tmp/x", None).unwrap();
    let meta = create_run_meta("p", "20260511000000-aaaa", "/tmp/x", RunType::Scan);
    assert!(matches!(meta.phase, RunPhase::Running));
    write_run_meta(&root, &meta).unwrap();

    complete_run(&root, "p", "20260511000000-aaaa", RunPhase::Done).unwrap();
    let runs = list_runs(&root, "p").unwrap();
    assert_eq!(runs.len(), 1);
    assert!(matches!(runs[0].phase, RunPhase::Done));
    assert!(runs[0].completed_at.is_some());
}

#[test]
fn complete_run_missing_returns_none() {
    let (_d, root) = env();
    ensure_project(&root, "p", "/tmp/x", None).unwrap();
    let r = complete_run(&root, "p", "20260101000000-zzzz", RunPhase::Done).unwrap();
    assert!(r.is_none());
}

#[test]
fn list_runs_sorts_newest_first() {
    let (_d, root) = env();
    ensure_project(&root, "p", "/tmp/x", None).unwrap();
    for id in ["20260101000000-aaaa", "20260601000000-bbbb", "20260301000000-cccc"] {
        let m = create_run_meta("p", id, "/tmp/x", RunType::Scan);
        write_run_meta(&root, &m).unwrap();
    }
    let runs = list_runs(&root, "p").unwrap();
    let ids: Vec<_> = runs.iter().map(|r| r.run_id.as_str()).collect();
    assert_eq!(
        ids,
        vec!["20260601000000-bbbb", "20260301000000-cccc", "20260101000000-aaaa"]
    );
}

#[test]
fn file_record_path_rejects_unsafe_segments() {
    let root = DataRoot::from_path("data");
    assert!(file_record_path(&root, "p", "../etc/passwd").is_err());
    assert!(file_record_path(&root, "p", "/abs").is_err());
    assert!(file_record_path(&root, "..", "x.ts").is_err());
}

#[test]
fn run_id_generation_is_unique_and_well_formed() {
    use deepsec_core::generate_run_id;
    let mut ids = std::collections::HashSet::new();
    for _ in 0..100 {
        let id = generate_run_id();
        // shape: YYYYMMDDHHMMSS-XXXX
        assert_eq!(id.len(), 14 + 1 + 4, "got: {id}");
        assert!(id.chars().nth(14) == Some('-'));
        assert!(id[..14].chars().all(|c| c.is_ascii_digit()));
        assert!(id[15..].chars().all(|c| c.is_ascii_hexdigit()));
        assert!(ids.insert(id));
    }
}

#[test]
fn data_root_from_env_falls_back_to_default() {
    // SAFETY: tests are serial within a single binary; remove + read in the same scope
    // is OK because no other test reads DEEPSEC_DATA_ROOT.
    unsafe {
        std::env::remove_var("DEEPSEC_DATA_ROOT");
    }
    let r = DataRoot::from_env();
    assert_eq!(r.as_path(), std::path::Path::new("data"));
}
