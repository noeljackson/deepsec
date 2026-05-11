//! Wire-compatibility checks. These freeze the on-disk JSON shape so a
//! future refactor can't silently break `data/<projectId>/` directories
//! written by older deepsec versions.
//!
//! If a test here fails after a deliberate schema change, update the
//! fixture in this file with the new shape AND bump a compat note in
//! `MIGRATION.md`. Don't just delete the test.

use deepsec_core::{
    AnalysisEntry, AnalysisPhase, CandidateMatch, Confidence, FileRecord, FileStatus, Finding,
    GitCommitter, GitInfo, ProjectConfig, RefusalReport, Revalidation, RevalidationVerdict,
    RunMeta, Severity, Triage, TriagePriority, Usage,
};

#[test]
fn file_record_roundtrips_camelcase_fields() {
    // This JSON mirrors what `packages/core/src/types.ts` writes today.
    let json = r#"{
      "filePath": "src/api/users.ts",
      "projectId": "p",
      "candidates": [
        {
          "vulnSlug": "sql-injection-string-concat",
          "lineNumbers": [42, 43],
          "snippet": "let x = q",
          "matchedPattern": "SQL injection"
        }
      ],
      "lastScannedAt": "2026-05-11T00:00:00Z",
      "lastScannedRunId": "20260511000000-aaaa",
      "fileHash": "deadbeef",
      "findings": [
        {
          "severity": "HIGH",
          "vulnSlug": "sql-injection-string-concat",
          "title": "T",
          "description": "D",
          "lineNumbers": [42],
          "recommendation": "Use parameterized queries",
          "confidence": "high",
          "producedByRunId": "20260511000000-aaaa"
        }
      ],
      "analysisHistory": [
        {
          "runId": "20260511000000-aaaa",
          "investigatedAt": "2026-05-11T00:01:00Z",
          "durationMs": 1234,
          "agentType": "anthropic",
          "model": "claude-sonnet-4-6",
          "modelConfig": {},
          "findingCount": 1,
          "phase": "process",
          "costUsd": 0.01,
          "usage": {
            "inputTokens": 100,
            "outputTokens": 50,
            "cacheReadInputTokens": 0,
            "cacheCreationInputTokens": 0
          }
        }
      ],
      "status": "analyzed",
      "lockedByRunId": null
    }"#;
    let rec: FileRecord = serde_json::from_str(json).expect("parse");
    assert_eq!(rec.file_path, "src/api/users.ts");
    assert_eq!(rec.candidates.len(), 1);
    assert_eq!(rec.candidates[0].vuln_slug, "sql-injection-string-concat");
    assert_eq!(rec.findings.len(), 1);
    assert!(matches!(rec.findings[0].severity, Severity::High));
    assert!(matches!(rec.findings[0].confidence, Confidence::High));
    assert!(matches!(rec.status, FileStatus::Analyzed));
    let entry = &rec.analysis_history[0];
    assert!(matches!(entry.phase, Some(AnalysisPhase::Process)));
    assert_eq!(entry.cost_usd, Some(0.01));
    assert_eq!(entry.usage.as_ref().unwrap().input_tokens, 100);

    // Re-serialize and re-parse; must be lossless.
    let body = serde_json::to_string(&rec).unwrap();
    let rec2: FileRecord = serde_json::from_str(&body).unwrap();
    assert_eq!(rec.file_path, rec2.file_path);
    assert_eq!(
        rec.candidates[0].vuln_slug,
        rec2.candidates[0].vuln_slug
    );
}

#[test]
fn finding_serializes_with_camelcase_field_names() {
    let f = Finding {
        severity: Severity::Critical,
        vuln_slug: "x".into(),
        title: "T".into(),
        description: "D".into(),
        line_numbers: vec![1],
        recommendation: "R".into(),
        confidence: Confidence::Medium,
        triage: Some(Triage {
            priority: TriagePriority::P0,
            exploitability: deepsec_core::Exploitability::Trivial,
            impact: deepsec_core::Impact::Critical,
            reasoning: "high".into(),
            triaged_at: "2026-05-11T00:00:00Z".into(),
            model: "m".into(),
        }),
        revalidation: Some(Revalidation {
            verdict: RevalidationVerdict::TruePositive,
            reasoning: "still there".into(),
            adjusted_severity: None,
            revalidated_at: "2026-05-11T00:00:00Z".into(),
            run_id: "r".into(),
            model: "m".into(),
        }),
        produced_by_run_id: Some("r".into()),
    };
    let body = serde_json::to_string(&f).unwrap();
    assert!(body.contains("\"vulnSlug\""));
    assert!(body.contains("\"lineNumbers\""));
    assert!(body.contains("\"producedByRunId\""));
    assert!(body.contains("\"severity\":\"CRITICAL\""));
    assert!(body.contains("\"confidence\":\"medium\""));
    assert!(body.contains("\"verdict\":\"true-positive\""));
    assert!(body.contains("\"priority\":\"P0\""));
    assert!(body.contains("\"exploitability\":\"trivial\""));
}

#[test]
fn run_meta_accepts_camelcase_layout() {
    let json = r#"{
      "runId": "20260511000000-aaaa",
      "projectId": "p",
      "rootPath": "./app",
      "createdAt": "2026-05-11T00:00:00Z",
      "type": "process",
      "phase": "done",
      "scannerConfig": {
        "matcherSlugs": ["a", "b"],
        "mode": "full"
      },
      "processorConfig": {
        "agentType": "anthropic",
        "model": "claude-sonnet-4-6",
        "modelConfig": {},
        "invocationMode": "scan"
      },
      "stats": {
        "filesScanned": 10,
        "candidatesFound": 5,
        "filesProcessed": 5,
        "findingsCount": 2,
        "totalCostUsd": 0.05,
        "totalInputTokens": 1000,
        "totalOutputTokens": 500,
        "totalDurationMs": 12345
      }
    }"#;
    let m: RunMeta = serde_json::from_str(json).expect("parse");
    assert_eq!(m.run_id, "20260511000000-aaaa");
    assert_eq!(m.stats.files_scanned, Some(10));
    assert_eq!(m.stats.total_cost_usd, Some(0.05));
    let sc = m.scanner_config.as_ref().unwrap();
    assert_eq!(sc.matcher_slugs.len(), 2);
}

#[test]
fn project_config_camelcase_roundtrip() {
    let p = ProjectConfig {
        project_id: "p".into(),
        root_path: "./app".into(),
        created_at: "2026-05-11T00:00:00Z".into(),
        github_url: Some("https://github.com/o/r/blob/main".into()),
    };
    let body = serde_json::to_string(&p).unwrap();
    assert!(body.contains("\"projectId\""));
    assert!(body.contains("\"rootPath\""));
    assert!(body.contains("\"createdAt\""));
    assert!(body.contains("\"githubUrl\""));
    let _back: ProjectConfig = serde_json::from_str(&body).unwrap();
}

#[test]
fn legacy_analysis_entry_without_phase_field_still_parses() {
    // Older runs predate the `phase` field. They must still load.
    let json = r#"{
      "runId": "old",
      "investigatedAt": "2026-01-01T00:00:00Z",
      "durationMs": 0,
      "agentType": "anthropic",
      "model": "m",
      "modelConfig": {},
      "findingCount": 0
    }"#;
    let a: AnalysisEntry = serde_json::from_str(json).expect("parse");
    assert!(a.phase.is_none());
    assert!(a.cost_usd.is_none());
    assert!(a.usage.is_none());
}

#[test]
fn legacy_file_record_without_locked_at_still_parses() {
    let json = r#"{
      "filePath": "x.ts",
      "projectId": "p",
      "candidates": [],
      "lastScannedAt": "2026-01-01T00:00:00Z",
      "lastScannedRunId": "r",
      "fileHash": "h",
      "findings": [],
      "analysisHistory": [],
      "status": "processing",
      "lockedByRunId": "r"
    }"#;
    let rec: FileRecord = serde_json::from_str(json).expect("parse");
    assert!(matches!(rec.status, FileStatus::Processing));
    assert!(rec.locked_at.is_none());
}

#[test]
fn git_info_serializes_camelcase() {
    let g = GitInfo {
        recent_committers: vec![GitCommitter {
            name: "n".into(),
            email: "e".into(),
            date: "2026-01-01T00:00:00Z".into(),
        }],
        enriched_at: "2026-01-01T00:00:00Z".into(),
        ownership: None,
    };
    let body = serde_json::to_string(&g).unwrap();
    assert!(body.contains("\"recentCommitters\""));
    assert!(body.contains("\"enrichedAt\""));
}

#[test]
fn refusal_report_round_trips() {
    let r = RefusalReport {
        refused: true,
        reason: Some("policy".into()),
        skipped: None,
        raw: Some("raw response".into()),
    };
    let body = serde_json::to_string(&r).unwrap();
    let r2: RefusalReport = serde_json::from_str(&body).unwrap();
    assert!(r2.refused);
    assert_eq!(r2.reason.as_deref(), Some("policy"));
}

#[test]
fn usage_defaults_zero_when_missing() {
    let u: Usage = serde_json::from_str("{}").unwrap();
    assert_eq!(u.input_tokens, 0);
    assert_eq!(u.output_tokens, 0);
    assert_eq!(u.cache_read_input_tokens, 0);
    assert_eq!(u.cache_creation_input_tokens, 0);
}

#[test]
fn severity_ordering_matches_rank() {
    assert!(Severity::Critical > Severity::High);
    assert!(Severity::High > Severity::Medium);
    assert!(Severity::Medium > Severity::Low);
    // rank() agrees with PartialOrd
    assert!(Severity::Critical.rank() > Severity::High.rank());
}
