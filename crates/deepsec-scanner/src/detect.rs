//! Lightweight tech detection: read top-level manifests, derive a tag set.

use deepsec_core::ids::now_iso;
use deepsec_core::{DataRoot, data_dir, paths::PathError};
use serde::{Deserialize, Serialize};
use std::path::Path;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DetectedTech {
    pub tags: Vec<String>,
    pub sentinels: Vec<String>,
    #[serde(rename = "detectedAt")]
    pub detected_at: String,
    #[serde(rename = "rootPath")]
    pub root_path: String,
}

fn read(root: &Path, name: &str) -> Option<String> {
    fs_err::read_to_string(root.join(name)).ok()
}

fn read_any(root: &Path, names: &[&str]) -> Option<String> {
    for n in names {
        if let Some(s) = read(root, n) {
            return Some(s);
        }
    }
    None
}

fn contains_any(hay: &str, needles: &[&str]) -> bool {
    needles.iter().any(|n| hay.contains(n))
}

pub fn detect_tech(root: &Path) -> DetectedTech {
    let mut tags: Vec<String> = Vec::new();
    let mut sentinels: Vec<String> = Vec::new();

    if let Some(pkg) = read(root, "package.json") {
        sentinels.push("package.json".into());
        tags.push("node".into());
        if pkg.contains("\"typescript\"") || root.join("tsconfig.json").exists() {
            tags.push("typescript".into());
        }
        if contains_any(&pkg, &["\"next\"", "\"@vercel/next\""]) {
            tags.push("nextjs".into());
        }
        if pkg.contains("\"react\"") {
            tags.push("react".into());
        }
        if pkg.contains("\"express\"") {
            tags.push("express".into());
        }
        if pkg.contains("\"fastify\"") {
            tags.push("fastify".into());
        }
        if pkg.contains("\"@nestjs/core\"") {
            tags.push("nestjs".into());
        }
        if pkg.contains("\"koa\"") {
            tags.push("koa".into());
        }
        if pkg.contains("\"@hapi/hapi\"") {
            tags.push("hapi".into());
        }
        if pkg.contains("\"hono\"") {
            tags.push("hono".into());
        }
        if pkg.contains("\"remix\"") || pkg.contains("\"@remix-run/") {
            tags.push("remix".into());
        }
        if pkg.contains("\"@sveltejs/kit\"") {
            tags.push("sveltekit".into());
        }
        if pkg.contains("\"astro\"") {
            tags.push("astro".into());
        }
        if pkg.contains("\"@solidjs/start\"") {
            tags.push("solidstart".into());
        }
        if pkg.contains("\"nuxt\"") {
            tags.push("nuxt".into());
        }
        if pkg.contains("\"graphql\"") || pkg.contains("\"@apollo/server\"") {
            tags.push("graphql".into());
        }
    }

    if read(root, "requirements.txt").is_some()
        || read(root, "pyproject.toml").is_some()
        || read(root, "setup.py").is_some()
    {
        sentinels.push("python".into());
        tags.push("python".into());
        if let Some(deps) = read_any(root, &["requirements.txt", "pyproject.toml", "setup.py"]) {
            if deps.to_lowercase().contains("django") {
                tags.push("django".into());
            }
            if deps.to_lowercase().contains("fastapi") {
                tags.push("fastapi".into());
            }
            if deps.to_lowercase().contains("flask") {
                tags.push("flask".into());
            }
            if deps.to_lowercase().contains("starlette") {
                tags.push("starlette".into());
            }
        }
    }

    if read(root, "Gemfile").is_some() {
        sentinels.push("Gemfile".into());
        tags.push("ruby".into());
        if let Some(gem) = read(root, "Gemfile") {
            if gem.contains("'rails'") || gem.contains("\"rails\"") {
                tags.push("rails".into());
            }
            if gem.contains("'sinatra'") {
                tags.push("sinatra".into());
            }
        }
    }

    if let Some(gomod) = read(root, "go.mod") {
        sentinels.push("go.mod".into());
        tags.push("go".into());
        if gomod.contains("gin-gonic/gin") {
            tags.push("gin".into());
        }
        if gomod.contains("labstack/echo") {
            tags.push("echo".into());
        }
        if gomod.contains("gofiber/fiber") {
            tags.push("fiber".into());
        }
        if gomod.contains("go-chi/chi") {
            tags.push("chi".into());
        }
    }

    if let Some(cargo) = read(root, "Cargo.toml") {
        sentinels.push("Cargo.toml".into());
        tags.push("rust".into());
        if cargo.contains("axum") {
            tags.push("axum".into());
        }
        if cargo.contains("actix-web") {
            tags.push("actix".into());
        }
        if cargo.contains("rocket") {
            tags.push("rocket".into());
        }
        if cargo.contains("warp") {
            tags.push("warp".into());
        }
    }

    if read(root, "composer.json").is_some() {
        sentinels.push("composer.json".into());
        tags.push("php".into());
    }

    if read_any(root, &["pom.xml", "build.gradle", "build.gradle.kts"]).is_some() {
        tags.push("jvm".into());
    }

    if read(root, "Dockerfile").is_some() {
        sentinels.push("Dockerfile".into());
        tags.push("docker".into());
    }

    if root.join(".github/workflows").is_dir() {
        sentinels.push(".github/workflows".into());
        tags.push("github-actions".into());
    }

    tags.sort();
    tags.dedup();

    DetectedTech {
        tags,
        sentinels,
        detected_at: now_iso(),
        root_path: root.display().to_string(),
    }
}

fn tech_json_path(root: &DataRoot, project_id: &str) -> Result<std::path::PathBuf, PathError> {
    Ok(data_dir(root, project_id)?.join("tech.json"))
}

pub fn read_tech_json(
    root: &DataRoot,
    project_id: &str,
) -> Result<Option<DetectedTech>, anyhow::Error> {
    let p = tech_json_path(root, project_id)?;
    match fs_err::read_to_string(&p) {
        Ok(s) => Ok(Some(serde_json::from_str(&s)?)),
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => Ok(None),
        Err(e) => Err(e.into()),
    }
}

pub fn write_tech_json(
    root: &DataRoot,
    project_id: &str,
    tech: &DetectedTech,
) -> Result<(), anyhow::Error> {
    let p = tech_json_path(root, project_id)?;
    if let Some(parent) = p.parent() {
        fs_err::create_dir_all(parent)?;
    }
    fs_err::write(p, serde_json::to_string_pretty(tech)?)?;
    Ok(())
}
