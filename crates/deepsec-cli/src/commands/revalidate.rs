use crate::backend::resolve_backend;
use crate::config_loader::Context;
use anyhow::Result;
use clap::Args as ClapArgs;
use colored::Colorize;
use deepsec_processor::{RevalidateOptions, run_revalidate};

#[derive(Debug, ClapArgs)]
pub struct Args {
    #[arg(long)]
    pub project_id: String,
    #[arg(long)]
    pub agent: Option<String>,
    #[arg(long)]
    pub model: Option<String>,
    #[arg(long)]
    pub filter: Option<String>,
    #[arg(long)]
    pub force: bool,
}

pub async fn run(args: Args, ctx: &Context) -> Result<()> {
    let proj = ctx.project(&args.project_id)?;
    let default_agent = ctx.config.as_ref().and_then(|c| c.default_agent.as_deref());
    crate::preflight::check(args.agent.as_deref().or(default_agent))?;
    let backend = resolve_backend(args.agent.as_deref(), args.model.as_deref(), default_agent)?;
    let opts = RevalidateOptions {
        project_id: args.project_id.clone(),
        project_root: proj.root,
        data_root: ctx.data_root.clone(),
        backend,
        filter_prefix: args.filter,
        force: args.force,
    };
    let out = run_revalidate(opts).await?;
    println!(
        "{} run={} revalidated={} TP={} FP={} fixed={} uncertain={}",
        "revalidate".bold().green(),
        out.run_id,
        out.revalidated,
        out.true_positives,
        out.false_positives,
        out.fixed,
        out.uncertain
    );
    Ok(())
}
