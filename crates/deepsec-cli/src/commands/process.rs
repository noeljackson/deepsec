use crate::backend::resolve_backend;
use crate::config_loader::Context;
use crate::file_sources::{FileSourceArgs, resolve as resolve_files};
use anyhow::Result;
use clap::Args as ClapArgs;
use colored::Colorize;
use deepsec_processor::{ProcessOptions, run_process};
use deepsec_scanner::{ScanOptions, read_tech_json, scan_files};

#[derive(Debug, ClapArgs)]
pub struct Args {
    #[arg(long)]
    pub project_id: String,
    /// AI backend ('anthropic' | 'openai').
    #[arg(long)]
    pub agent: Option<String>,
    /// Override the backend model.
    #[arg(long)]
    pub model: Option<String>,
    /// Files-per-batch sent to the model.
    #[arg(long, default_value_t = 5)]
    pub batch_size: usize,
    /// Max concurrent in-flight batches.
    #[arg(long, default_value_t = 4)]
    pub concurrency: usize,
    /// Cap total files processed.
    #[arg(long)]
    pub limit: Option<usize>,
    /// Only process files whose path starts with this prefix.
    #[arg(long)]
    pub filter: Option<String>,
    /// Only process candidates with these slugs (comma-separated).
    #[arg(long)]
    pub only_slugs: Option<String>,
    /// Skip candidates with these slugs (comma-separated).
    #[arg(long)]
    pub skip_slugs: Option<String>,

    /// Direct mode: explicit file list. Mutually exclusive with
    /// --files-from / --diff. Bypasses scanner-state filter.
    #[arg(long, value_delimiter = ',')]
    pub files: Option<Vec<String>>,
    /// Direct mode: read file paths from this file ("-" reads stdin).
    #[arg(long)]
    pub files_from: Option<std::path::PathBuf>,
    /// Direct mode: process only files changed vs this git ref.
    #[arg(long)]
    pub diff: Option<String>,

    /// Wave marker. Files already analyzed at this marker with the
    /// same agent are skipped. See `process --reinvestigate N` in the
    /// TS docs.
    #[arg(long)]
    pub reinvestigate: Option<u32>,
}

pub async fn run(args: Args, ctx: &Context) -> Result<()> {
    let proj = ctx.project(&args.project_id)?;
    let default_agent = ctx.config.as_ref().and_then(|c| c.default_agent.as_deref());

    crate::preflight::check(args.agent.as_deref().or(default_agent))?;

    let backend = resolve_backend(args.agent.as_deref(), args.model.as_deref(), default_agent)?;

    let resolved = resolve_files(
        FileSourceArgs {
            files: args.files.as_deref(),
            files_from: args.files_from.as_deref(),
            diff: args.diff.as_deref(),
        },
        &proj.root,
    )?;

    let (direct_files, direct_source) = if let Some(r) = resolved {
        // In direct mode we scan the listed files first so FileRecords
        // exist and have current candidates before we send to the agent.
        let scan_opts = ScanOptions {
            project_id: args.project_id.clone(),
            root: proj.root.clone(),
            data_root: ctx.data_root.clone(),
            matcher_only: ctx
                .config
                .as_ref()
                .map(|c| c.matchers.only.clone())
                .unwrap_or_default(),
            matcher_exclude: ctx
                .config
                .as_ref()
                .map(|c| c.matchers.exclude.clone())
                .unwrap_or_default(),
            github_url: proj.decl.github_url.clone(),
        };
        scan_files(&scan_opts, &r.files, &r.source)?;
        (Some(r.files), Some(r.source))
    } else {
        (None, None)
    };

    let detected = read_tech_json(&ctx.data_root, &args.project_id).ok().flatten();

    let opts = ProcessOptions {
        project_id: args.project_id.clone(),
        project_root: proj.root,
        data_root: ctx.data_root.clone(),
        backend,
        batch_size: args.batch_size,
        concurrency: args.concurrency,
        limit: args.limit,
        filter_prefix: args.filter,
        only_slugs: args
            .only_slugs
            .as_deref()
            .map(super::scan_split_csv)
            .unwrap_or_default(),
        skip_slugs: args
            .skip_slugs
            .as_deref()
            .map(super::scan_split_csv)
            .unwrap_or_default(),
        project_info: proj.decl.info_markdown.clone(),
        prompt_append: proj.decl.prompt_append.clone(),
        detected,
        direct_files,
        direct_source,
        reinvestigate_marker: args.reinvestigate,
    };

    let out = run_process(opts).await?;
    println!(
        "{} run={} batches={} files_analyzed={} findings={} errors={}{}",
        "process".bold().green(),
        out.run_id,
        out.batches_run,
        out.analysis_count,
        out.finding_count,
        out.error_batch_count,
        if out.quota_exhausted {
            " (quota exhausted)".yellow().to_string()
        } else {
            String::new()
        }
    );
    Ok(())
}
