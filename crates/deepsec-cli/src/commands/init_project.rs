use crate::config_loader::Context;
use anyhow::Result;
use clap::Args as ClapArgs;
use deepsec_core::ensure_project;

#[derive(Debug, ClapArgs)]
pub struct Args {
    #[arg(long)]
    pub project_id: String,
    #[arg(long, default_value = ".")]
    pub root: String,
    #[arg(long)]
    pub github_url: Option<String>,
}

pub fn run(args: Args, ctx: &Context) -> Result<()> {
    let cfg = ensure_project(
        &ctx.data_root,
        &args.project_id,
        &args.root,
        args.github_url.as_deref(),
    )?;
    println!(
        "Initialized project '{}' at {}",
        cfg.project_id, cfg.root_path
    );
    Ok(())
}
