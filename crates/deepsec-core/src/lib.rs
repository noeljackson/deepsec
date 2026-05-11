//! deepsec-core: types, paths, schemas, and persistence helpers.
//!
//! The data model mirrors the TypeScript implementation in
//! `packages/core/src/types.ts`. On-disk JSON is wire-compatible so a
//! repo's `data/<projectId>/` directory written by the TS deepsec can
//! be read by the Rust deepsec and vice versa.

pub mod config;
pub mod ids;
pub mod paths;
pub mod runs;
pub mod store;
pub mod types;

pub use config::{
    DeepsecConfig, MatcherFilter, ProjectDeclaration, find_config_file, load_config,
};
pub use ids::generate_run_id;
pub use paths::{
    DataRoot, assert_safe_file_path, assert_safe_segment, data_dir, file_record_path,
    files_dir, project_config_path, report_csv_path, report_json_path, report_md_path,
    reports_dir, run_meta_path, runs_dir,
};
pub use runs::{
    RunMeta, ScannerConfig, ProcessorConfig, RunStats, RunType, RunPhase, ScannerMode,
    InvocationMode, complete_run, create_run_meta, read_run_meta, write_run_meta,
};
pub use store::{
    StoreError, file_hash_hex, load_all_file_records, read_file_record, read_project_config,
    write_file_record, write_project_config, ensure_project,
};
pub use types::{
    AnalysisEntry, AnalysisPhase, CandidateMatch, Confidence, Exploitability, FileRecord,
    FileStatus, Finding, GitCommitter, GitInfo, Impact, OwnershipApprover, OwnershipContributor,
    OwnershipData, OwnershipEscalationTeam, ProjectConfig, RefusalReport, Revalidation,
    RevalidationVerdict, Severity, Triage, TriagePriority, Usage,
};
