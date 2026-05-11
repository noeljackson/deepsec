use crate::config_loader::Context;
use anyhow::{Context as _, Result, anyhow};
use clap::Args as ClapArgs;
use colored::Colorize;
use std::process::Command;

#[derive(Debug, ClapArgs)]
pub struct Args {
    /// Subset of the data dir to commit. Defaults to the entire
    /// data dir.
    #[arg(long)]
    pub paths: Option<Vec<String>>,
    /// Commit message. Defaults to a generated one.
    #[arg(short, long)]
    pub message: Option<String>,
    /// Repo to operate on. Defaults to the directory containing
    /// the config file (or cwd).
    #[arg(long)]
    pub repo: Option<std::path::PathBuf>,
    /// Don't fail if there is nothing to commit.
    #[arg(long)]
    pub allow_empty: bool,
}

pub fn run(args: Args, ctx: &Context) -> Result<()> {
    let repo = args.repo.unwrap_or_else(|| {
        ctx.config_path
            .as_ref()
            .and_then(|p| p.parent().map(|p| p.to_path_buf()))
            .unwrap_or_else(|| ctx.cwd.clone())
    });

    if !repo.join(".git").exists() {
        return Err(anyhow!(
            "{} is not a git repository (pass --repo)",
            repo.display()
        ));
    }

    let data_path = ctx.data_root.as_path();
    let rel_data = data_path
        .strip_prefix(&repo)
        .map(|p| p.to_path_buf())
        .unwrap_or_else(|_| data_path.to_path_buf());

    let mut add = Command::new("git");
    add.arg("-C").arg(&repo).arg("add").arg("--");
    if let Some(paths) = args.paths {
        for p in paths {
            add.arg(p);
        }
    } else {
        add.arg(&rel_data);
    }
    let status = add.status().context("running git add")?;
    if !status.success() {
        return Err(anyhow!("git add failed"));
    }

    // Check if there's anything staged.
    let diff = Command::new("git")
        .arg("-C")
        .arg(&repo)
        .arg("diff")
        .arg("--cached")
        .arg("--quiet")
        .status()
        .context("running git diff --cached")?;
    if diff.success() {
        // exit 0 → nothing staged
        if args.allow_empty {
            println!("{} no changes to commit", "data-commit".dimmed());
            return Ok(());
        }
        return Err(anyhow!("no changes staged"));
    }

    let message = args.message.unwrap_or_else(|| {
        format!("deepsec: update {} ({})",
            rel_data.display(),
            time::OffsetDateTime::now_utc()
                .format(&time::format_description::well_known::Iso8601::DEFAULT)
                .unwrap_or_default())
    });

    let commit = Command::new("git")
        .arg("-C")
        .arg(&repo)
        .arg("commit")
        .arg("-m")
        .arg(&message)
        .status()
        .context("running git commit")?;
    if !commit.success() {
        return Err(anyhow!("git commit failed"));
    }
    println!("{} {}", "data-commit".bold().green(), message);
    Ok(())
}
