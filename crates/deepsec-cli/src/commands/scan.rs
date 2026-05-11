use crate::config_loader::Context;
use crate::file_sources::{FileSourceArgs, resolve};
use anyhow::Result;
use clap::Args as ClapArgs;
use colored::Colorize;
use deepsec_scanner::{ScanOptions, scan, scan_files};

#[derive(Debug, ClapArgs)]
pub struct Args {
    /// Project id (from deepsec.config.toml).
    #[arg(long)]
    pub project_id: String,
    /// Override project root. Defaults to config's project root.
    #[arg(long)]
    pub root: Option<String>,
    /// Only run these matcher slugs (comma-separated).
    #[arg(long)]
    pub matchers: Option<String>,
    /// Skip these matcher slugs (comma-separated).
    #[arg(long)]
    pub skip_matchers: Option<String>,

    /// Explicit file list (repeatable or comma-separated). Mutually
    /// exclusive with --files-from / --diff.
    #[arg(long, value_delimiter = ',')]
    pub files: Option<Vec<String>>,
    /// Read file paths from this file ("-" reads stdin).
    #[arg(long)]
    pub files_from: Option<std::path::PathBuf>,
    /// Scan only files changed vs this git ref (e.g. `origin/main`).
    #[arg(long)]
    pub diff: Option<String>,
}

pub fn run(args: Args, ctx: &Context) -> Result<()> {
    let proj = ctx.project(&args.project_id)?;
    let root = match args.root {
        Some(r) => std::path::PathBuf::from(r),
        None => proj.root.clone(),
    };

    let mut only: Vec<String> = args
        .matchers
        .as_deref()
        .map(super::scan_split_csv)
        .unwrap_or_default();
    let mut exclude: Vec<String> = args
        .skip_matchers
        .as_deref()
        .map(super::scan_split_csv)
        .unwrap_or_default();
    if let Some(cfg) = &ctx.config {
        if only.is_empty() {
            only = cfg.matchers.only.clone();
        }
        if exclude.is_empty() {
            exclude = cfg.matchers.exclude.clone();
        }
    }

    let opts = ScanOptions {
        project_id: args.project_id.clone(),
        root: root.clone(),
        data_root: ctx.data_root.clone(),
        matcher_only: only,
        matcher_exclude: exclude,
        github_url: proj.decl.github_url.clone(),
    };

    let resolved = resolve(
        FileSourceArgs {
            files: args.files.as_deref(),
            files_from: args.files_from.as_deref(),
            diff: args.diff.as_deref(),
        },
        &root,
    )?;

    if let Some(r) = resolved {
        let out = scan_files(&opts, &r.files, &r.source)?;
        println!(
            "{} run={} mode=files source={} files={} candidates={}",
            "scan".bold().green(),
            out.run_id,
            r.source,
            out.files_scanned,
            out.candidate_count
        );
        println!("  tech tags: {}", out.detected.tags.join(", "));
        println!(
            "  matchers active={} skipped={}",
            out.active_matchers.len(),
            out.skipped_matchers.len()
        );
        return Ok(());
    }

    let out = scan(&opts)?;
    println!(
        "{} run={} files={} candidates={}",
        "scan".bold().green(),
        out.run_id,
        out.files_scanned,
        out.candidate_count
    );
    println!("  tech tags: {}", out.detected.tags.join(", "));
    println!(
        "  matchers active={} skipped={}",
        out.active_matchers.len(),
        out.skipped_matchers.len()
    );
    if !out.language_stats.is_empty() {
        println!("  by language:");
        for s in &out.language_stats {
            println!(
                "    {:>12}: {:>5} files  hits in {:>4}",
                s.language, s.files_scanned, s.files_with_match
            );
        }
    }
    Ok(())
}
