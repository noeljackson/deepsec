use crate::detect::{DetectedTech, detect_tech, write_tech_json};
use crate::gate::evaluate_gate;
use crate::registry::MatcherRegistry;
use crate::matchers::NoiseTier;
use deepsec_core::ids::{generate_run_id, now_iso};
use deepsec_core::store::{file_hash_hex, read_file_record, write_file_record};
use deepsec_core::{
    CandidateMatch, DataRoot, FileRecord, FileStatus, RunPhase, RunType,
    ScannerConfig, ScannerMode, complete_run, create_run_meta, ensure_project, write_run_meta,
};
use globset::{Glob, GlobSetBuilder};
use std::collections::BTreeMap;
use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct ScanOptions {
    pub project_id: String,
    pub root: PathBuf,
    pub data_root: DataRoot,
    pub matcher_only: Vec<String>,
    pub matcher_exclude: Vec<String>,
    pub github_url: Option<String>,
}

#[derive(Debug, Clone, Default)]
pub struct LanguageStat {
    pub language: String,
    pub files_scanned: usize,
    pub files_with_match: usize,
}

#[derive(Debug, Clone)]
pub struct ScanOutcome {
    pub run_id: String,
    pub files_scanned: usize,
    pub candidate_count: usize,
    pub detected: DetectedTech,
    pub active_matchers: Vec<String>,
    pub skipped_matchers: Vec<String>,
    pub language_stats: Vec<LanguageStat>,
}

#[derive(Debug, Clone)]
pub struct ScanFilesOutcome {
    pub run_id: String,
    pub files_scanned: usize,
    pub candidate_count: usize,
    pub detected: DetectedTech,
    pub active_matchers: Vec<String>,
    pub skipped_matchers: Vec<String>,
}

fn lang_for(rel: &Path) -> &'static str {
    match rel.extension().and_then(|e| e.to_str()) {
        Some("ts") | Some("tsx") => "typescript",
        Some("js") | Some("jsx") | Some("mjs") | Some("cjs") => "javascript",
        Some("py") => "python",
        Some("rb") => "ruby",
        Some("go") => "go",
        Some("rs") => "rust",
        Some("java") => "java",
        Some("kt") | Some("kts") => "kotlin",
        Some("cs") => "csharp",
        Some("php") => "php",
        Some("swift") => "swift",
        Some("ex") | Some("exs") => "elixir",
        Some("erl") => "erlang",
        Some("clj") | Some("cljs") => "clojure",
        Some("cr") => "crystal",
        Some("scala") => "scala",
        Some("c") | Some("h") => "c",
        Some("cpp") | Some("cc") | Some("hpp") => "cpp",
        Some("dart") => "dart",
        _ => "other",
    }
}

/// Run a full-repo scan: walk the project, evaluate matcher gates,
/// match against every file, write FileRecords, write RunMeta.
pub fn scan(opts: &ScanOptions) -> anyhow::Result<ScanOutcome> {
    ensure_project(
        &opts.data_root,
        &opts.project_id,
        opts.root.to_string_lossy().as_ref(),
        opts.github_url.as_deref(),
    )?;

    let run_id = generate_run_id();
    let mut meta = create_run_meta(
        &opts.project_id,
        &run_id,
        opts.root.to_string_lossy().as_ref(),
        RunType::Scan,
    );
    write_run_meta(&opts.data_root, &meta)?;

    let detected = detect_tech(&opts.root);
    write_tech_json(&opts.data_root, &opts.project_id, &detected)?;

    let mut registry = MatcherRegistry::with_builtin()?;
    registry.apply_filter(&opts.matcher_only, &opts.matcher_exclude);

    let mut active = Vec::new();
    let mut skipped = Vec::new();
    for m in registry.iter() {
        if evaluate_gate(m.requires(), &detected, &opts.root) {
            active.push(m.slug().to_string());
        } else {
            skipped.push(m.slug().to_string());
        }
    }

    let files = crate::walker::walk_project(&opts.root);
    let mut candidate_count = 0usize;
    let mut by_lang: BTreeMap<&'static str, LanguageStat> = BTreeMap::new();

    for rel in &files {
        let rel_str = rel.to_string_lossy().replace('\\', "/");
        let abs = opts.root.join(rel);
        let content = match fs_err::read_to_string(&abs) {
            Ok(s) => s,
            Err(_) => continue,
        };
        let normalized = content.replace("\r\n", "\n");

        let mut matches: Vec<CandidateMatch> = Vec::new();
        for m in registry.iter() {
            if !active.iter().any(|s| s == m.slug()) {
                continue;
            }
            if !matches_pattern(m.file_patterns(), &rel_str) {
                continue;
            }
            matches.extend(m.matches(&normalized, &rel_str));
        }

        let lang = lang_for(rel);
        let st = by_lang.entry(lang).or_insert_with(|| LanguageStat {
            language: lang.into(),
            ..Default::default()
        });
        st.files_scanned += 1;
        if !matches.is_empty() {
            st.files_with_match += 1;
        }
        candidate_count += matches.len();
        upsert_record(&opts.data_root, &opts.project_id, &rel_str, &run_id, &normalized, matches)?;
    }

    let total_files = files.len();
    meta.scanner_config = Some(ScannerConfig {
        matcher_slugs: active.clone(),
        mode: Some(ScannerMode::Full),
        source: None,
        file_count: None,
    });
    meta.stats.files_scanned = Some(total_files);
    meta.stats.candidates_found = Some(candidate_count);
    write_run_meta(&opts.data_root, &meta)?;
    complete_run(&opts.data_root, &opts.project_id, &run_id, RunPhase::Done)?;

    Ok(ScanOutcome {
        run_id,
        files_scanned: total_files,
        candidate_count,
        detected,
        active_matchers: active,
        skipped_matchers: skipped,
        language_stats: by_lang.into_values().collect(),
    })
}

/// Scan only the explicitly listed file paths. Writes a FileRecord for
/// every listed path, even when no matchers fire.
pub fn scan_files(opts: &ScanOptions, files: &[String], source: &str) -> anyhow::Result<ScanFilesOutcome> {
    ensure_project(
        &opts.data_root,
        &opts.project_id,
        opts.root.to_string_lossy().as_ref(),
        opts.github_url.as_deref(),
    )?;
    let run_id = generate_run_id();
    let mut meta = create_run_meta(
        &opts.project_id,
        &run_id,
        opts.root.to_string_lossy().as_ref(),
        RunType::Scan,
    );
    write_run_meta(&opts.data_root, &meta)?;

    let detected = detect_tech(&opts.root);
    write_tech_json(&opts.data_root, &opts.project_id, &detected)?;

    let mut registry = MatcherRegistry::with_builtin()?;
    registry.apply_filter(&opts.matcher_only, &opts.matcher_exclude);

    let mut active = Vec::new();
    let mut skipped = Vec::new();
    for m in registry.iter() {
        if evaluate_gate(m.requires(), &detected, &opts.root) {
            active.push(m.slug().to_string());
        } else {
            skipped.push(m.slug().to_string());
        }
    }

    let mut candidate_count = 0usize;
    for rel_str in files {
        let rel = Path::new(rel_str);
        let abs = opts.root.join(rel);
        let content = match fs_err::read_to_string(&abs) {
            Ok(s) => s,
            Err(_) => String::new(),
        };
        let normalized = content.replace("\r\n", "\n");
        let mut matches: Vec<CandidateMatch> = Vec::new();
        for m in registry.iter() {
            if !active.iter().any(|s| s == m.slug()) {
                continue;
            }
            if !matches_pattern(m.file_patterns(), rel_str) {
                continue;
            }
            matches.extend(m.matches(&normalized, rel_str));
        }
        candidate_count += matches.len();
        upsert_record(&opts.data_root, &opts.project_id, rel_str, &run_id, &normalized, matches)?;
    }

    meta.scanner_config = Some(ScannerConfig {
        matcher_slugs: active.clone(),
        mode: Some(ScannerMode::Files),
        source: Some(source.into()),
        file_count: Some(files.len()),
    });
    meta.stats.files_scanned = Some(files.len());
    meta.stats.candidates_found = Some(candidate_count);
    write_run_meta(&opts.data_root, &meta)?;
    complete_run(&opts.data_root, &opts.project_id, &run_id, RunPhase::Done)?;

    Ok(ScanFilesOutcome {
        run_id,
        files_scanned: files.len(),
        candidate_count,
        detected,
        active_matchers: active,
        skipped_matchers: skipped,
    })
}

fn matches_pattern(patterns: &[String], rel: &str) -> bool {
    let mut builder = GlobSetBuilder::new();
    let mut any = false;
    for p in patterns {
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
    set.is_match(rel)
}

fn upsert_record(
    root: &DataRoot,
    project_id: &str,
    rel: &str,
    run_id: &str,
    content: &str,
    mut new_matches: Vec<CandidateMatch>,
) -> anyhow::Result<()> {
    let hash = file_hash_hex(content.as_bytes());
    let now = now_iso();
    let existing = read_file_record(root, project_id, rel).ok().flatten();

    let mut rec = existing.unwrap_or(FileRecord {
        file_path: rel.into(),
        project_id: project_id.into(),
        candidates: Vec::new(),
        last_scanned_at: now.clone(),
        last_scanned_run_id: run_id.into(),
        file_hash: hash.clone(),
        findings: Vec::new(),
        analysis_history: Vec::new(),
        git_info: None,
        status: FileStatus::Pending,
        locked_by_run_id: None,
        locked_at: None,
    });

    rec.last_scanned_at = now;
    rec.last_scanned_run_id = run_id.into();
    rec.file_hash = hash;

    // dedupe new + existing candidates by (slug, pattern, line numbers)
    let mut seen: std::collections::HashSet<String> = rec
        .candidates
        .iter()
        .map(|c| format!("{}|{}|{:?}", c.vuln_slug, c.matched_pattern, c.line_numbers))
        .collect();
    new_matches.retain(|c| seen.insert(format!("{}|{}|{:?}", c.vuln_slug, c.matched_pattern, c.line_numbers)));
    rec.candidates.extend(new_matches);

    // If this file is pending and we found new candidates, it stays pending.
    // Don't downgrade `analyzed` files just because a re-scan ran.
    if matches!(rec.status, FileStatus::Pending) && rec.candidates.is_empty() {
        // no candidates → nothing to investigate yet
    }

    write_file_record(root, &rec)?;
    Ok(())
}

/// Group FileRecords into batches by directory, splitting oversized
/// directories. Matches the TS implementation's behavior.
pub fn batch_candidates(records: &[FileRecord], max_batch: usize) -> Vec<Vec<&FileRecord>> {
    let mut by_dir: BTreeMap<String, Vec<&FileRecord>> = BTreeMap::new();
    for r in records {
        let dir = std::path::Path::new(&r.file_path)
            .parent()
            .and_then(|p| p.to_str())
            .unwrap_or("")
            .to_string();
        by_dir.entry(dir).or_default().push(r);
    }
    let mut out = Vec::new();
    let mut current: Vec<&FileRecord> = Vec::new();
    for (_dir, files) in by_dir {
        for chunk in files.chunks(max_batch) {
            if current.len() + chunk.len() <= max_batch {
                current.extend(chunk);
            } else {
                if !current.is_empty() {
                    out.push(std::mem::take(&mut current));
                }
                out.push(chunk.to_vec());
            }
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}

/// Score a file by its highest-precision matcher hit. Lower = higher priority.
pub fn noise_score(rec: &FileRecord, registry: &MatcherRegistry) -> u32 {
    let mut best: u32 = NoiseTier::Noisy.rank() + 1;
    for c in &rec.candidates {
        let t = registry.noise_tier(&c.vuln_slug);
        if t.rank() < best {
            best = t.rank();
        }
    }
    best
}
