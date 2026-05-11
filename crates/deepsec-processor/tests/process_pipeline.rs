//! End-to-end tests for run_process / run_revalidate / run_triage
//! using a mock AgentBackend. Builds FileRecords on disk, drives the
//! pipeline, and asserts the post-state.

mod mock_backend;

use deepsec_core::{
    AnalysisPhase, CandidateMatch, DataRoot, FileRecord, FileStatus, RevalidationVerdict,
    Severity, ensure_project, write_file_record,
};
use deepsec_processor::{
    ProcessOptions, RevalidateOptions, TriageOptions, run_process, run_revalidate, run_triage,
};
use mock_backend::MockBackend;
use std::path::PathBuf;
use std::sync::Arc;
use std::sync::atomic::Ordering;
use tempfile::TempDir;

struct Env {
    pub dir: TempDir,
    pub data_root: DataRoot,
    pub project_id: String,
    pub project_root: PathBuf,
}

impl Env {
    fn new() -> Self {
        let dir = tempfile::tempdir().unwrap();
        let data_root = DataRoot::from_path(dir.path().join("data"));
        let project_id = "test".to_string();
        let project_root = dir.path().join("app");
        fs_err::create_dir_all(&project_root).unwrap();
        ensure_project(&data_root, &project_id, project_root.to_str().unwrap(), None).unwrap();
        Self {
            dir,
            data_root,
            project_id,
            project_root,
        }
    }

    fn write_source(&self, rel: &str, content: &str) {
        let abs = self.project_root.join(rel);
        if let Some(p) = abs.parent() {
            fs_err::create_dir_all(p).unwrap();
        }
        fs_err::write(abs, content).unwrap();
    }

    fn seed_record(&self, rel: &str, status: FileStatus, candidate_slug: &str) -> FileRecord {
        self.write_source(rel, "// dummy source\nlet x = 1;\n");
        let rec = FileRecord {
            file_path: rel.into(),
            project_id: self.project_id.clone(),
            candidates: vec![CandidateMatch {
                vuln_slug: candidate_slug.into(),
                line_numbers: vec![1],
                snippet: "let x = 1;".into(),
                matched_pattern: "test".into(),
            }],
            last_scanned_at: "2026-01-01T00:00:00Z".into(),
            last_scanned_run_id: "seed-run".into(),
            file_hash: "abc".into(),
            findings: Vec::new(),
            analysis_history: Vec::new(),
            git_info: None,
            status,
            locked_by_run_id: None,
            locked_at: None,
        };
        write_file_record(&self.data_root, &rec).unwrap();
        rec
    }

    fn read_back(&self, rel: &str) -> FileRecord {
        let p = deepsec_core::file_record_path(&self.data_root, &self.project_id, rel).unwrap();
        let body = fs_err::read_to_string(p).unwrap();
        serde_json::from_str(&body).unwrap()
    }
}

fn opts(env: &Env, backend: Arc<MockBackend>) -> ProcessOptions {
    ProcessOptions {
        project_id: env.project_id.clone(),
        project_root: env.project_root.clone(),
        data_root: env.data_root.clone(),
        backend,
        batch_size: 2,
        concurrency: 2,
        limit: None,
        filter_prefix: None,
        only_slugs: Vec::new(),
        skip_slugs: Vec::new(),
        project_info: None,
        prompt_append: None,
        detected: None,
        direct_files: None,
        direct_source: None,
        reinvestigate_marker: None,
    }
}

#[tokio::test]
async fn process_writes_findings_and_marks_analyzed() {
    let env = Env::new();
    env.seed_record("src/a.ts", FileStatus::Pending, "mock-slug");
    env.seed_record("src/b.ts", FileStatus::Pending, "mock-slug");

    let backend = Arc::new(MockBackend::new());
    let outcome = run_process(opts(&env, backend.clone())).await.unwrap();

    assert_eq!(outcome.analysis_count, 2);
    assert_eq!(outcome.finding_count, 2);
    assert!(!outcome.quota_exhausted);

    for path in ["src/a.ts", "src/b.ts"] {
        let rec = env.read_back(path);
        assert!(matches!(rec.status, FileStatus::Analyzed), "{path}");
        assert_eq!(rec.findings.len(), 1, "{path}");
        assert_eq!(rec.findings[0].vuln_slug, "mock-slug");
        assert_eq!(
            rec.findings[0].produced_by_run_id.as_deref(),
            Some(outcome.run_id.as_str())
        );
        assert_eq!(rec.analysis_history.len(), 1);
        assert!(matches!(
            rec.analysis_history[0].phase,
            Some(AnalysisPhase::Process)
        ));
        assert_eq!(rec.analysis_history[0].finding_count, 1);
        assert!(rec.locked_by_run_id.is_none());
    }
    assert_eq!(backend.investigate_calls.load(Ordering::SeqCst), 1);
}

#[tokio::test]
async fn process_skips_analyzed_files() {
    let env = Env::new();
    env.seed_record("src/a.ts", FileStatus::Analyzed, "mock-slug");
    env.seed_record("src/b.ts", FileStatus::Pending, "mock-slug");

    let backend = Arc::new(MockBackend::new());
    let outcome = run_process(opts(&env, backend.clone())).await.unwrap();
    assert_eq!(outcome.analysis_count, 1);
    assert_eq!(env.read_back("src/a.ts").findings.len(), 0);
    assert_eq!(env.read_back("src/b.ts").findings.len(), 1);
}

#[tokio::test]
async fn process_filter_prefix_narrows_work() {
    let env = Env::new();
    env.seed_record("src/api/a.ts", FileStatus::Pending, "mock-slug");
    env.seed_record("src/lib/b.ts", FileStatus::Pending, "mock-slug");

    let mut o = opts(&env, Arc::new(MockBackend::new()));
    o.filter_prefix = Some("src/api/".into());
    let outcome = run_process(o).await.unwrap();
    assert_eq!(outcome.analysis_count, 1);
    assert_eq!(env.read_back("src/api/a.ts").findings.len(), 1);
    assert_eq!(env.read_back("src/lib/b.ts").findings.len(), 0);
}

#[tokio::test]
async fn process_only_slugs_filters_candidates() {
    let env = Env::new();
    env.seed_record("src/a.ts", FileStatus::Pending, "wanted-slug");
    env.seed_record("src/b.ts", FileStatus::Pending, "other-slug");

    let mut o = opts(&env, Arc::new(MockBackend::new()));
    o.only_slugs = vec!["wanted-slug".into()];
    let outcome = run_process(o).await.unwrap();
    assert_eq!(outcome.analysis_count, 1);
}

#[tokio::test]
async fn process_limit_caps_files() {
    let env = Env::new();
    for i in 0..5 {
        env.seed_record(&format!("src/f{i}.ts"), FileStatus::Pending, "mock-slug");
    }
    let mut o = opts(&env, Arc::new(MockBackend::new()));
    o.limit = Some(2);
    let outcome = run_process(o).await.unwrap();
    assert_eq!(outcome.analysis_count, 2);
}

#[tokio::test]
async fn process_quota_exhausted_releases_locks_to_pending() {
    let env = Env::new();
    for i in 0..6 {
        env.seed_record(&format!("src/f{i}.ts"), FileStatus::Pending, "mock-slug");
    }
    let mut backend = MockBackend::new();
    backend.quota_after = Some(1); // succeed once, then quota out
    let backend = Arc::new(backend);

    let mut o = opts(&env, backend.clone());
    o.batch_size = 1;
    o.concurrency = 1; // deterministic order
    let outcome = run_process(o).await.unwrap();
    assert!(outcome.quota_exhausted);
    // At least one file made it through.
    assert!(outcome.analysis_count >= 1);
    // The remaining files should not be stuck in `processing`.
    let mut pending = 0;
    let mut analyzed = 0;
    for i in 0..6 {
        let rec = env.read_back(&format!("src/f{i}.ts"));
        match rec.status {
            FileStatus::Pending => pending += 1,
            FileStatus::Analyzed => analyzed += 1,
            other => panic!("unexpected status: {other:?}"),
        }
        assert!(rec.locked_by_run_id.is_none(), "lock not released");
    }
    assert!(pending >= 1);
    assert!(analyzed >= 1);
}

#[tokio::test]
async fn process_refusal_records_into_analysis_history() {
    let env = Env::new();
    env.seed_record("src/a.ts", FileStatus::Pending, "mock-slug");
    let mut backend = MockBackend::new();
    backend.return_refusal = true;
    let outcome = run_process(opts(&env, Arc::new(backend))).await.unwrap();
    assert_eq!(outcome.error_batch_count, 1);

    let rec = env.read_back("src/a.ts");
    assert!(matches!(rec.status, FileStatus::Error));
    assert_eq!(rec.analysis_history.len(), 1);
    let refusal = rec.analysis_history[0].refusal.as_ref().expect("refusal");
    assert!(refusal.refused);
    assert!(refusal.reason.as_deref().unwrap_or("").contains("refusal"));
}

#[tokio::test]
async fn process_concurrency_runs_in_parallel() {
    let env = Env::new();
    for i in 0..8 {
        env.seed_record(&format!("src/f{i}.ts"), FileStatus::Pending, "mock-slug");
    }
    let mut backend = MockBackend::new();
    backend.delay_ms = 200;
    let backend = Arc::new(backend);

    let mut o = opts(&env, backend.clone());
    o.batch_size = 1;
    o.concurrency = 8;

    let start = std::time::Instant::now();
    let outcome = run_process(o).await.unwrap();
    let elapsed = start.elapsed().as_millis();

    assert_eq!(outcome.analysis_count, 8);
    // Serial would be 8 * 200ms = 1600ms. Parallel should be ~200ms +
    // overhead. Asserting < 800ms gives a comfortable margin while still
    // catching a regression to serial execution.
    assert!(
        elapsed < 800,
        "expected parallel batches; elapsed={elapsed}ms"
    );
}

#[tokio::test]
async fn process_direct_mode_processes_analyzed_files() {
    let env = Env::new();
    // An already-analyzed file would normally be skipped.
    env.seed_record("src/a.ts", FileStatus::Analyzed, "mock-slug");
    env.seed_record("src/b.ts", FileStatus::Pending, "mock-slug");

    let mut o = opts(&env, Arc::new(MockBackend::new()));
    o.direct_files = Some(vec!["src/a.ts".into()]);
    o.direct_source = Some("test:direct".into());
    let outcome = run_process(o).await.unwrap();

    // Only the directly-listed file should have been processed.
    assert_eq!(outcome.analysis_count, 1);
    assert!(!env.read_back("src/a.ts").findings.is_empty());
    assert!(env.read_back("src/b.ts").findings.is_empty());
}

#[tokio::test]
async fn process_reinvestigate_skips_files_at_same_wave() {
    let env = Env::new();
    let mut rec = env.seed_record("src/a.ts", FileStatus::Pending, "mock-slug");
    // Stamp a prior analysis at wave=1 for the mock backend.
    rec.analysis_history.push(deepsec_core::AnalysisEntry {
        run_id: "old-run".into(),
        investigated_at: "2026-01-01T00:00:00Z".into(),
        duration_ms: 0,
        duration_api_ms: None,
        agent_type: "anthropic".into(),
        model: "mock".into(),
        model_config: Default::default(),
        agent_session_id: None,
        finding_count: 0,
        num_turns: None,
        phase: Some(AnalysisPhase::Process),
        cost_usd: None,
        usage: None,
        refusal: None,
        codex_stderr: None,
        reinvestigate_marker: Some(1),
    });
    write_file_record(&env.data_root, &rec).unwrap();

    let mut o = opts(&env, Arc::new(MockBackend::new()));
    o.reinvestigate_marker = Some(1);
    let outcome = run_process(o).await.unwrap();
    // Wave-1 work was already done for this file → no analysis this run.
    assert_eq!(outcome.analysis_count, 0);

    // Wave 2 should pick it up.
    let mut o2 = opts(&env, Arc::new(MockBackend::new()));
    o2.reinvestigate_marker = Some(2);
    let outcome = run_process(o2).await.unwrap();
    assert_eq!(outcome.analysis_count, 1);
    let rec = env.read_back("src/a.ts");
    let new_entry = rec
        .analysis_history
        .iter()
        .find(|e| e.reinvestigate_marker == Some(2))
        .expect("wave-2 entry");
    assert_eq!(new_entry.reinvestigate_marker, Some(2));
}

#[tokio::test]
async fn revalidate_assigns_verdict_to_existing_findings() {
    let env = Env::new();
    let mut rec = env.seed_record("src/a.ts", FileStatus::Analyzed, "mock-slug");
    rec.findings.push(deepsec_core::Finding {
        severity: Severity::High,
        vuln_slug: "mock-slug".into(),
        title: "T".into(),
        description: "D".into(),
        line_numbers: vec![1],
        recommendation: "R".into(),
        confidence: deepsec_core::Confidence::High,
        triage: None,
        revalidation: None,
        produced_by_run_id: Some("prior".into()),
    });
    write_file_record(&env.data_root, &rec).unwrap();

    let backend = Arc::new(MockBackend::new());
    let outcome = run_revalidate(RevalidateOptions {
        project_id: env.project_id.clone(),
        project_root: env.project_root.clone(),
        data_root: env.data_root.clone(),
        backend: backend.clone(),
        filter_prefix: None,
        force: false,
    })
    .await
    .unwrap();
    assert_eq!(outcome.revalidated, 1);
    assert_eq!(outcome.true_positives, 1);
    let rec = env.read_back("src/a.ts");
    let r = rec.findings[0].revalidation.as_ref().expect("revalidation");
    assert!(matches!(r.verdict, RevalidationVerdict::TruePositive));
}

#[tokio::test]
async fn revalidate_skips_already_revalidated_unless_forced() {
    let env = Env::new();
    let mut rec = env.seed_record("src/a.ts", FileStatus::Analyzed, "mock-slug");
    rec.findings.push(deepsec_core::Finding {
        severity: Severity::High,
        vuln_slug: "mock-slug".into(),
        title: "T".into(),
        description: "D".into(),
        line_numbers: vec![1],
        recommendation: "R".into(),
        confidence: deepsec_core::Confidence::High,
        triage: None,
        revalidation: Some(deepsec_core::Revalidation {
            verdict: RevalidationVerdict::FalsePositive,
            reasoning: "prior".into(),
            adjusted_severity: None,
            revalidated_at: "2026-01-01T00:00:00Z".into(),
            run_id: "prior".into(),
            model: "prior".into(),
        }),
        produced_by_run_id: Some("prior".into()),
    });
    write_file_record(&env.data_root, &rec).unwrap();

    let backend = Arc::new(MockBackend::new());
    let outcome = run_revalidate(RevalidateOptions {
        project_id: env.project_id.clone(),
        project_root: env.project_root.clone(),
        data_root: env.data_root.clone(),
        backend: backend.clone(),
        filter_prefix: None,
        force: false,
    })
    .await
    .unwrap();
    assert_eq!(outcome.revalidated, 0);

    // With force=true, the mock returns true-positive overriding the prior FP.
    let outcome = run_revalidate(RevalidateOptions {
        project_id: env.project_id.clone(),
        project_root: env.project_root.clone(),
        data_root: env.data_root.clone(),
        backend: backend.clone(),
        filter_prefix: None,
        force: true,
    })
    .await
    .unwrap();
    assert_eq!(outcome.revalidated, 1);
    let rec = env.read_back("src/a.ts");
    assert!(matches!(
        rec.findings[0].revalidation.as_ref().unwrap().verdict,
        RevalidationVerdict::TruePositive
    ));
}

#[tokio::test]
async fn triage_assigns_priority_to_unverdicted_findings() {
    let env = Env::new();
    let mut rec = env.seed_record("src/a.ts", FileStatus::Analyzed, "mock-slug");
    rec.findings.push(deepsec_core::Finding {
        severity: Severity::High,
        vuln_slug: "mock-slug".into(),
        title: "T".into(),
        description: "D".into(),
        line_numbers: vec![1],
        recommendation: "R".into(),
        confidence: deepsec_core::Confidence::High,
        triage: None,
        revalidation: None,
        produced_by_run_id: Some("prior".into()),
    });
    write_file_record(&env.data_root, &rec).unwrap();

    let backend = Arc::new(MockBackend::new());
    let outcome = run_triage(TriageOptions {
        project_id: env.project_id.clone(),
        project_root: env.project_root.clone(),
        data_root: env.data_root.clone(),
        backend: backend.clone(),
        filter_prefix: None,
        force: false,
    })
    .await
    .unwrap();
    assert_eq!(outcome.triaged, 1);
    let rec = env.read_back("src/a.ts");
    let t = rec.findings[0].triage.as_ref().expect("triage");
    assert!(matches!(t.priority, deepsec_core::TriagePriority::P1));
    assert!(matches!(t.exploitability, deepsec_core::Exploitability::Moderate));
    assert!(matches!(t.impact, deepsec_core::Impact::High));
}

#[tokio::test]
async fn finding_dedupe_by_slug_and_title() {
    let env = Env::new();
    env.seed_record("src/a.ts", FileStatus::Pending, "mock-slug");

    // First run: 1 finding from the mock.
    let backend = Arc::new(MockBackend::new());
    run_process(opts(&env, backend.clone())).await.unwrap();
    let after_first = env.read_back("src/a.ts").findings.len();
    assert_eq!(after_first, 1);

    // Reset to pending so the same record gets re-processed.
    let mut rec = env.read_back("src/a.ts");
    rec.status = FileStatus::Pending;
    write_file_record(&env.data_root, &rec).unwrap();

    // Same mock returns a finding with the same (slug, title) — should
    // be deduped, leaving 1 finding total.
    run_process(opts(&env, Arc::new(MockBackend::new()))).await.unwrap();
    let after_second = env.read_back("src/a.ts").findings.len();
    assert_eq!(after_second, 1, "duplicate finding was not deduped");
}
