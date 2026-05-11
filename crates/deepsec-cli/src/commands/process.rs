use crate::backend::resolve_backend;
use crate::config_loader::Context;
use anyhow::Result;
use clap::Args as ClapArgs;
use colored::Colorize;
use deepsec_processor::{ProcessOptions, run_process};
use deepsec_scanner::read_tech_json;

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
}

pub async fn run(args: Args, ctx: &Context) -> Result<()> {
    let proj = ctx.project(&args.project_id)?;
    let default_agent = ctx.config.as_ref().and_then(|c| c.default_agent.as_deref());
    let backend = resolve_backend(args.agent.as_deref(), args.model.as_deref(), default_agent)?;
    let detected = read_tech_json(&ctx.data_root, &args.project_id).ok().flatten();

    let opts = ProcessOptions {
        project_id: args.project_id.clone(),
        project_root: proj.root,
        data_root: ctx.data_root.clone(),
        backend,
        batch_size: args.batch_size,
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
