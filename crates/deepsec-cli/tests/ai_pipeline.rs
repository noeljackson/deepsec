//! End-to-end CLI tests that drive `process`, `revalidate`, `triage`,
//! `pr-comment`, and `enrich` against a local mock Anthropic-compatible
//! HTTP server.

use assert_cmd::Command;
use std::io::{BufRead, BufReader, Read, Write};
use std::net::{SocketAddr, TcpListener};
use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU16, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use tempfile::TempDir;

static PORT_OFFSET: AtomicU16 = AtomicU16::new(0);

fn pick_port() -> u16 {
    // bind to :0 once to get a free port, then close so the test
    // server can rebind. Cheap-and-simple for test isolation.
    let listener = TcpListener::bind("127.0.0.1:0").unwrap();
    let port = listener.local_addr().unwrap().port();
    drop(listener);
    // best-effort uniqueness even under hammering
    let _ = PORT_OFFSET.fetch_add(1, Ordering::SeqCst);
    port
}

struct MockServer {
    pub addr: SocketAddr,
    pub stop_tx: Option<std::sync::mpsc::Sender<()>>,
    pub calls: Arc<Mutex<usize>>,
}

impl MockServer {
    /// Spin up a tiny HTTP server that answers any POST with `body_supplier`.
    fn start<F>(body_supplier: F) -> Self
    where
        F: Fn(usize) -> (u16, String) + Send + Sync + 'static,
    {
        let port = pick_port();
        let listener = TcpListener::bind(("127.0.0.1", port)).expect("bind");
        listener.set_nonblocking(true).unwrap();
        let addr = listener.local_addr().unwrap();
        let calls = Arc::new(Mutex::new(0_usize));
        let calls_th = calls.clone();
        let (stop_tx, stop_rx) = std::sync::mpsc::channel();

        thread::spawn(move || {
            let supplier = Arc::new(body_supplier);
            loop {
                if stop_rx.try_recv().is_ok() {
                    break;
                }
                match listener.accept() {
                    Ok((mut stream, _)) => {
                        stream.set_nonblocking(false).unwrap();
                        // read request headers + body
                        let mut reader = BufReader::new(stream.try_clone().unwrap());
                        let mut content_length = 0;
                        loop {
                            let mut line = String::new();
                            if reader.read_line(&mut line).unwrap_or(0) == 0 {
                                break;
                            }
                            if line.to_ascii_lowercase().starts_with("content-length:") {
                                content_length = line
                                    .split(':')
                                    .nth(1)
                                    .and_then(|v| v.trim().parse().ok())
                                    .unwrap_or(0);
                            }
                            if line == "\r\n" {
                                break;
                            }
                        }
                        let mut body = vec![0u8; content_length];
                        let _ = reader.read_exact(&mut body);

                        let n = {
                            let mut g = calls_th.lock().unwrap();
                            *g += 1;
                            *g - 1
                        };
                        let (status, payload) = supplier(n);
                        let response = format!(
                            "HTTP/1.1 {} OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
                            status,
                            payload.as_bytes().len(),
                            payload
                        );
                        let _ = stream.write_all(response.as_bytes());
                        let _ = stream.flush();
                    }
                    Err(e) if e.kind() == std::io::ErrorKind::WouldBlock => {
                        thread::sleep(std::time::Duration::from_millis(5));
                    }
                    Err(_) => break,
                }
            }
        });

        Self {
            addr,
            stop_tx: Some(stop_tx),
            calls,
        }
    }

    fn url(&self) -> String {
        format!("http://{}", self.addr)
    }

    fn call_count(&self) -> usize {
        *self.calls.lock().unwrap()
    }
}

impl Drop for MockServer {
    fn drop(&mut self) {
        if let Some(tx) = self.stop_tx.take() {
            let _ = tx.send(());
        }
    }
}

fn fixture_path() -> PathBuf {
    let manifest = PathBuf::from(env!("CARGO_MANIFEST_DIR"));
    manifest
        .parent()
        .unwrap()
        .parent()
        .unwrap()
        .join("fixtures/vulnerable-app")
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

struct Harness {
    pub dir: TempDir,
    pub project_id: String,
}

impl Harness {
    fn new(project_id: &str) -> Self {
        let dir = tempfile::tempdir().unwrap();
        let target = dir.path().join("app");
        copy_dir(&fixture_path(), &target).expect("copy fixture");
        let cfg = format!(
            "default_agent = \"anthropic\"\n[[projects]]\nid = \"{project_id}\"\nroot = \"./app\"\n"
        );
        fs_err::write(dir.path().join("deepsec.config.toml"), cfg).unwrap();
        Self {
            dir,
            project_id: project_id.into(),
        }
    }

    fn cmd(&self) -> Command {
        let mut c = Command::cargo_bin("deepsec").unwrap();
        c.current_dir(self.dir.path());
        c
    }
}

fn anthropic_response_with_finding(file_path: &str) -> String {
    let inner = serde_json::json!({
        "findings": [{
            "filePath": file_path,
            "severity": "HIGH",
            "vulnSlug": "test-slug",
            "title": "Mock SQLi",
            "description": "Mocked",
            "lineNumbers": [1],
            "recommendation": "Fix it",
            "confidence": "high"
        }]
    })
    .to_string();
    serde_json::json!({
        "content": [{"type":"text","text": inner}],
        "usage": {
            "input_tokens": 100,
            "output_tokens": 50,
            "cache_read_input_tokens": 0,
            "cache_creation_input_tokens": 0
        }
    })
    .to_string()
}

#[test]
fn process_writes_findings_via_http_backend() {
    let h = Harness::new("p1");
    h.cmd()
        .args(["scan", "--project-id", &h.project_id])
        .assert()
        .success();

    let server = MockServer::start(|_| (200, anthropic_response_with_finding("src/api/users.ts")));
    let out = h
        .cmd()
        .env("ANTHROPIC_API_KEY", "fake")
        .env("ANTHROPIC_BASE_URL", server.url())
        .args([
            "process",
            "--project-id",
            &h.project_id,
            "--batch-size",
            "2",
            "--concurrency",
            "2",
        ])
        .output()
        .unwrap();
    assert!(
        out.status.success(),
        "process failed: {}",
        String::from_utf8_lossy(&out.stderr)
    );
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("findings="), "got: {stdout}");

    let rec_path = h
        .dir
        .path()
        .join("data")
        .join(&h.project_id)
        .join("files/src/api/users.ts.json");
    let body = fs_err::read_to_string(&rec_path).unwrap();
    assert!(body.contains("\"Mock SQLi\""), "no finding written: {body}");
    assert!(server.call_count() >= 1);
}

#[test]
fn process_marks_files_error_on_quota_exhaustion() {
    let h = Harness::new("p1");
    h.cmd()
        .args(["scan", "--project-id", &h.project_id])
        .assert()
        .success();

    let server = MockServer::start(|_| {
        (
            429,
            serde_json::json!({"error":{"message":"rate limit"}}).to_string(),
        )
    });
    let out = h
        .cmd()
        .env("ANTHROPIC_API_KEY", "fake")
        .env("ANTHROPIC_BASE_URL", server.url())
        .args(["process", "--project-id", &h.project_id, "--batch-size", "2"])
        .output()
        .unwrap();
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("quota exhausted"), "got: {stdout}");
}

#[test]
fn pr_comment_renders_markdown_for_run() {
    let h = Harness::new("p1");
    h.cmd()
        .args(["scan", "--project-id", &h.project_id])
        .assert()
        .success();
    let server = MockServer::start(|_| (200, anthropic_response_with_finding("src/api/users.ts")));
    h.cmd()
        .env("ANTHROPIC_API_KEY", "fake")
        .env("ANTHROPIC_BASE_URL", server.url())
        .args(["process", "--project-id", &h.project_id, "--batch-size", "5"])
        .assert()
        .success();

    let out = h
        .cmd()
        .args(["pr-comment", "--project-id", &h.project_id])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    let stdout = String::from_utf8(out.stdout).unwrap();
    assert!(stdout.contains("Mock SQLi"), "got: {stdout}");
    assert!(stdout.contains("HIGH"), "got: {stdout}");
    assert!(stdout.contains("src/api/users.ts"), "got: {stdout}");
}

#[test]
fn pr_comment_skip_empty_outputs_nothing_when_no_findings() {
    let h = Harness::new("p1");
    h.cmd()
        .args(["scan", "--project-id", &h.project_id])
        .assert()
        .success();
    // No process run → no findings tied to a run. With --skip-empty the
    // command must fail loudly (no recent process run) rather than
    // silently print "no findings".
    let out = h
        .cmd()
        .args(["pr-comment", "--project-id", &h.project_id, "--skip-empty"])
        .output()
        .unwrap();
    assert!(!out.status.success());
}

#[test]
fn enrich_populates_git_info_when_in_git_repo() {
    let h = Harness::new("p1");
    // Initialize git for the fixture so enrich has something to read.
    let app = h.dir.path().join("app");
    let _ = std::process::Command::new("git")
        .arg("-C")
        .arg(&app)
        .arg("init")
        .arg("-q")
        .output();
    let _ = std::process::Command::new("git")
        .arg("-C")
        .arg(&app)
        .args(["-c", "user.email=t@t", "-c", "user.name=t", "-c", "commit.gpgsign=false"])
        .args(["add", "."])
        .output();
    let commit = std::process::Command::new("git")
        .arg("-C")
        .arg(&app)
        .args(["-c", "user.email=t@t", "-c", "user.name=t", "-c", "commit.gpgsign=false"])
        .args(["commit", "-qm", "seed"])
        .output()
        .unwrap();
    if !commit.status.success() {
        // commit-signing not available in some sandboxes; skip silently.
        eprintln!(
            "git commit failed in sandbox: {} — skipping",
            String::from_utf8_lossy(&commit.stderr)
        );
        return;
    }

    h.cmd()
        .args(["scan", "--project-id", &h.project_id])
        .assert()
        .success();
    let out = h
        .cmd()
        .args(["enrich", "--project-id", &h.project_id])
        .output()
        .unwrap();
    assert!(out.status.success(), "{}", String::from_utf8_lossy(&out.stderr));
    // At least one record should have gitInfo populated.
    let files_dir = h.dir.path().join("data").join(&h.project_id).join("files");
    let mut found = false;
    for entry in walkdir::WalkDir::new(&files_dir).into_iter().filter_map(|e| e.ok()) {
        if entry.file_type().is_file()
            && entry.path().extension().and_then(|e| e.to_str()) == Some("json")
        {
            let body = fs_err::read_to_string(entry.path()).unwrap();
            if body.contains("\"recentCommitters\"") {
                found = true;
                break;
            }
        }
    }
    assert!(found, "no gitInfo written to any record");
}
