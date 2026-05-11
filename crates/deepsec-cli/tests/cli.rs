//! End-to-end CLI tests against the vulnerable-app fixture.
//!
//! These exercise the deepsec binary as a subprocess and assert
//! behavior of the full pipeline: scan → status → export → report.
//! The AI-driven commands (process / revalidate / triage) are
//! covered separately by the smoke tests in CI because they need a
//! mock HTTP server.

use assert_cmd::Command;
use std::path::{Path, PathBuf};
use tempfile::TempDir;

fn fixture_path() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("fixtures/vulnerable-app")
}

struct Harness {
    pub dir: TempDir,
    pub project_id: String,
}

impl Harness {
    fn new(project_id: &str) -> Self {
        let dir = tempfile::tempdir().expect("tempdir");
        // Copy the fixture into the temp dir so scan resolves a real path.
        let target = dir.path().join("app");
        copy_dir(&fixture_path(), &target).expect("copy fixture");
        // Write a minimal deepsec.config.toml.
        let cfg = format!(
            "[[projects]]\nid = \"{project_id}\"\nroot = \"./app\"\n"
        );
        fs_err::write(dir.path().join("deepsec.config.toml"), cfg).expect("write config");
        Self {
            dir,
            project_id: project_id.into(),
        }
    }

    fn cmd(&self) -> Command {
        let mut c = Command::cargo_bin("deepsec").expect("binary");
        c.current_dir(self.dir.path());
        c
    }
}

fn copy_dir(src: &Path, dst: &Path) -> std::io::Result<()> {
    fs_err::create_dir_all(dst)?;
    for entry in fs_err::read_dir(src)? {
        let entry = entry?;
        let from = entry.path();
        let to = dst.join(entry.file_name());
        if entry.file_type()?.is_dir() {
            copy_dir(&from, &to)?;
        } else {
            fs_err::copy(&from, &to)?;
        }
    }
    Ok(())
}

#[test]
fn list_matchers_runs() {
    let h = Harness::new("p1");
    let out = h.cmd().arg("list-matchers").output().unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("matchers"));
    assert!(stdout.contains("auth-bypass"));
    assert!(stdout.contains("sql-injection-string-concat"));
}

#[test]
fn scan_finds_planted_vulnerabilities() {
    let h = Harness::new("p1");
    let out = h
        .cmd()
        .args(["scan", "--project-id", &h.project_id])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "scan failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    // The fixture contains 10+ planted vulnerabilities; we just check
    // that the scanner ran and produced a meaningful candidate count.
    assert!(stdout.contains("candidates="), "got: {stdout}");
    let candidates: usize = stdout
        .split("candidates=")
        .nth(1)
        .and_then(|s| s.split_whitespace().next())
        .and_then(|s| s.parse().ok())
        .unwrap_or(0);
    assert!(
        candidates >= 5,
        "expected at least 5 candidates in fixture, got {candidates}"
    );
}

#[test]
fn status_reports_pending_records() {
    let h = Harness::new("p1");
    h.cmd()
        .args(["scan", "--project-id", &h.project_id])
        .assert()
        .success();
    let out = h
        .cmd()
        .args(["status", "--project-id", &h.project_id])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("pending:"));
    assert!(stdout.contains("recent runs"));
}

#[test]
fn export_filters_by_severity() {
    let h = Harness::new("p1");
    h.cmd()
        .args(["scan", "--project-id", &h.project_id])
        .assert()
        .success();
    // No findings yet (no AI process run), so export returns empty.
    let out = h
        .cmd()
        .args([
            "export",
            "--project-id",
            &h.project_id,
            "--min-severity",
            "HIGH",
        ])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.trim() == "[]" || stdout.contains("filePath"));
}

#[test]
fn report_writes_files() {
    let h = Harness::new("p1");
    h.cmd()
        .args(["scan", "--project-id", &h.project_id])
        .assert()
        .success();
    h.cmd()
        .args(["report", "--project-id", &h.project_id])
        .assert()
        .success();
    let md = h
        .dir
        .path()
        .join("data")
        .join(&h.project_id)
        .join("reports/report.md");
    let json = h
        .dir
        .path()
        .join("data")
        .join(&h.project_id)
        .join("reports/report.json");
    let csv = h
        .dir
        .path()
        .join("data")
        .join(&h.project_id)
        .join("reports/report.csv");
    assert!(md.exists() && json.exists() && csv.exists());
}

#[test]
fn scan_files_mode_runs() {
    let h = Harness::new("p1");
    let out = h
        .cmd()
        .args([
            "scan",
            "--project-id",
            &h.project_id,
            "--files",
            "src/api/users.ts,src/api/admin.ts",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "scan --files failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("mode=files"), "got: {stdout}");
    assert!(stdout.contains("files=2"), "got: {stdout}");
}

#[test]
fn metrics_runs_without_findings() {
    let h = Harness::new("p1");
    h.cmd()
        .args(["scan", "--project-id", &h.project_id])
        .assert()
        .success();
    let out = h
        .cmd()
        .args(["metrics", "--project-id", &h.project_id])
        .output()
        .unwrap();
    assert!(out.status.success());
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("findings:"));
    assert!(stdout.contains("by slug:"));
}

#[test]
fn preflight_fails_without_api_key() {
    let h = Harness::new("p1");
    let out = h
        .cmd()
        .env_remove("ANTHROPIC_API_KEY")
        .args(["preflight", "--agent", "anthropic"])
        .output()
        .unwrap();
    assert!(!out.status.success());
    let stderr = String::from_utf8(out.stderr).unwrap();
    assert!(stderr.contains("ANTHROPIC_API_KEY"), "got: {stderr}");
}

#[test]
fn preflight_succeeds_with_api_key() {
    let h = Harness::new("p1");
    let out = h
        .cmd()
        .env("ANTHROPIC_API_KEY", "fake")
        .args(["preflight", "--agent", "anthropic"])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "preflight failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("preflight ok"));
}

#[test]
fn rejects_unknown_project() {
    let h = Harness::new("p1");
    let out = h
        .cmd()
        .args(["scan", "--project-id", "nonexistent"])
        .output()
        .unwrap();
    assert!(!out.status.success());
}
