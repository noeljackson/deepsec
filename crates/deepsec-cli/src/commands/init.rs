use crate::config_loader::Context;
use anyhow::Result;
use clap::Args as ClapArgs;
use std::path::PathBuf;

#[derive(Debug, ClapArgs)]
pub struct Args {
    /// Path to write deepsec.config.toml. Defaults to ./deepsec.config.toml.
    #[arg(long)]
    pub output: Option<PathBuf>,

    /// Project root for the initial project entry. Defaults to ".".
    #[arg(long, default_value = ".")]
    pub root: String,

    /// ID for the initial project entry.
    #[arg(long, default_value = "default")]
    pub project_id: String,

    /// Overwrite any existing config.
    #[arg(long)]
    pub force: bool,
}

const TEMPLATE: &str = r#"# deepsec configuration. See docs/configuration.md.

# Where deepsec writes file-record JSON and run metadata. Default: "data".
# data_dir = "data"

# Default AI backend: "anthropic" or "openai".
default_agent = "anthropic"

[matchers]
# Only run these matcher slugs. Empty = run everything bundled.
# only = []
# Never run these matcher slugs.
# exclude = []
# Load additional matcher TOML files (paths relative to this config).
# extra_paths = ["./my-matchers/internal.toml"]

[[projects]]
id = "PROJECT_ID"
root = "PROJECT_ROOT"
# github_url = "https://github.com/example/repo/blob/main"
# info_markdown = """
# Project-specific context surfaced to the AI agent.
# """
# prompt_append = "Pay extra attention to /api/admin/*."
priority_paths = []
"#;

pub fn run(args: Args, ctx: &Context) -> Result<()> {
    let path = args
        .output
        .unwrap_or_else(|| ctx.cwd.join("deepsec.config.toml"));
    if path.exists() && !args.force {
        anyhow::bail!("{} already exists. Use --force to overwrite.", path.display());
    }
    let body = TEMPLATE
        .replace("PROJECT_ID", &args.project_id)
        .replace("PROJECT_ROOT", &args.root);
    fs_err::write(&path, body)?;
    println!("Wrote {}", path.display());
    Ok(())
}
