use anyhow::Result;
use deepsec_core::{DataRoot, DeepsecConfig, ProjectDeclaration, find_config_file, load_config};
use std::path::{Path, PathBuf};

pub struct Context {
    pub config: Option<DeepsecConfig>,
    pub config_path: Option<PathBuf>,
    pub data_root: DataRoot,
    pub cwd: PathBuf,
}

impl Context {
    pub fn from_cli(config: Option<&Path>, data_dir: Option<&Path>) -> Result<Self> {
        let cwd = std::env::current_dir()?;
        let config_path = match config {
            Some(p) => Some(p.to_path_buf()),
            None => find_config_file(&cwd),
        };
        let config = match &config_path {
            Some(p) => Some(load_config(p)?),
            None => None,
        };
        let data_root = if let Some(d) = data_dir {
            DataRoot::from_path(d)
        } else if let Some(cfg) = config.as_ref().and_then(|c| c.data_dir.as_ref()) {
            // resolve relative to config file dir
            let base = config_path
                .as_ref()
                .and_then(|p| p.parent().map(Path::to_path_buf))
                .unwrap_or_else(|| cwd.clone());
            DataRoot::from_path(base.join(cfg))
        } else {
            DataRoot::from_env()
        };
        Ok(Self {
            config,
            config_path,
            data_root,
            cwd,
        })
    }

    pub fn project(&self, project_id: &str) -> Result<ResolvedProject> {
        let cfg = self
            .config
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("no deepsec.config.toml found; run `deepsec init`"))?;
        let proj = cfg
            .find_project(project_id)
            .ok_or_else(|| anyhow::anyhow!("project '{project_id}' not in config"))?;
        let base = self
            .config_path
            .as_ref()
            .and_then(|p| p.parent().map(Path::to_path_buf))
            .unwrap_or_else(|| self.cwd.clone());
        let root = if Path::new(&proj.root).is_absolute() {
            PathBuf::from(&proj.root)
        } else {
            base.join(&proj.root)
        };
        Ok(ResolvedProject {
            decl: proj.clone(),
            root,
        })
    }
}

pub struct ResolvedProject {
    pub decl: ProjectDeclaration,
    pub root: PathBuf,
}
