use crate::config_loader::Context;
use anyhow::Result;
use clap::Args as ClapArgs;
use colored::Colorize;
use deepsec_processor::{EnrichOptions, run_enrich};

#[derive(Debug, ClapArgs)]
pub struct Args {
    #[arg(long)]
    pub project_id: String,
    /// Only enrich paths starting with this prefix.
    #[arg(long)]
    pub filter: Option<String>,
    /// Max recent committers to record per file.
    #[arg(long, default_value_t = 5)]
    pub max_committers: usize,
    /// Re-enrich files that already have gitInfo.
    #[arg(long)]
    pub force: bool,
}

pub fn run(args: Args, ctx: &Context) -> Result<()> {
    let proj = ctx.project(&args.project_id)?;
    let opts = EnrichOptions {
        project_id: args.project_id.clone(),
        project_root: proj.root,
        data_root: ctx.data_root.clone(),
        filter_prefix: args.filter,
        max_committers: args.max_committers,
        force: args.force,
    };
    let out = run_enrich(opts)?;
    println!(
        "{} enriched={} skipped={}",
        "enrich".bold().green(),
        out.files_enriched,
        out.files_skipped
    );
    Ok(())
}
