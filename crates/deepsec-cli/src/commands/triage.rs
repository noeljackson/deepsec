use crate::backend::resolve_backend;
use crate::config_loader::Context;
use anyhow::Result;
use clap::Args as ClapArgs;
use colored::Colorize;
use deepsec_processor::{TriageOptions, run_triage};

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
    let backend = resolve_backend(args.agent.as_deref(), args.model.as_deref(), default_agent)?;
    let opts = TriageOptions {
        project_id: args.project_id.clone(),
        project_root: proj.root,
        data_root: ctx.data_root.clone(),
        backend,
        filter_prefix: args.filter,
        force: args.force,
    };
    let out = run_triage(opts).await?;
    println!(
        "{} run={} triaged={}",
        "triage".bold().green(),
        out.run_id,
        out.triaged
    );
    Ok(())
}
