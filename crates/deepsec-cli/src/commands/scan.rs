use crate::config_loader::Context;
use anyhow::Result;
use clap::Args as ClapArgs;
use colored::Colorize;
use deepsec_scanner::{ScanOptions, scan};

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
        .map(split_csv)
        .unwrap_or_default();
    let mut exclude: Vec<String> = args
        .skip_matchers
        .as_deref()
        .map(split_csv)
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
        root,
        data_root: ctx.data_root.clone(),
        matcher_only: only,
        matcher_exclude: exclude,
        github_url: proj.decl.github_url.clone(),
    };

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

fn split_csv(s: &str) -> Vec<String> {
    s.split(',')
        .map(|t| t.trim().to_string())
        .filter(|s| !s.is_empty())
        .collect()
}
