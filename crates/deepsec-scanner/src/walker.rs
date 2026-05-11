use ignore::WalkBuilder;
use std::path::{Path, PathBuf};

/// Directory names we always skip while walking a project. Mirrors the
/// `IGNORE_DIRS` constant in the TS scanner.
pub const IGNORE_DIRS: &[&str] = &[
    "node_modules",
    ".git",
    ".hg",
    ".svn",
    "dist",
    "build",
    "out",
    ".next",
    ".nuxt",
    ".turbo",
    ".cache",
    "coverage",
    "__pycache__",
    ".pytest_cache",
    ".mypy_cache",
    "target",
    "vendor",
    ".terraform",
    ".venv",
    "venv",
    ".tox",
    "deps",
    "Pods",
    ".idea",
    ".vscode",
];

const SKIP_EXTENSIONS: &[&str] = &[
    "md", "lock", "log", "min.js", "map", "ico", "png", "jpg", "jpeg", "gif", "webp", "svg",
    "pdf", "zip", "tar", "gz", "exe", "dll", "so", "dylib", "woff", "woff2", "ttf",
];

/// Walk the project, returning relative file paths. Honors .gitignore.
/// Files matching any [`SKIP_EXTENSIONS`] are dropped — they're noise
/// for source-level analysis.
pub fn walk_project(root: &Path) -> Vec<PathBuf> {
    let mut out = Vec::new();
    let mut builder = WalkBuilder::new(root);
    builder
        .hidden(false)
        .git_ignore(true)
        .git_global(true)
        .git_exclude(true)
        .follow_links(false);
    for d in IGNORE_DIRS {
        builder.add_custom_ignore_filename(d);
    }
    let walker = builder
        .filter_entry(|entry| {
            if let Some(name) = entry.file_name().to_str() {
                if entry.depth() > 0 && IGNORE_DIRS.contains(&name) {
                    return false;
                }
            }
            true
        })
        .build();

    for result in walker {
        let Ok(entry) = result else { continue };
        let path = entry.path();
        if !entry.file_type().map(|f| f.is_file()).unwrap_or(false) {
            continue;
        }
        if let Some(ext) = path.extension().and_then(|e| e.to_str()) {
            if SKIP_EXTENSIONS.iter().any(|s| s.eq_ignore_ascii_case(ext)) {
                continue;
            }
        }
        // skip very large files (>1 MiB) — the AI step caps file size
        // and matchers gain nothing from minified bundles.
        if let Ok(meta) = entry.metadata() {
            if meta.len() > 1_048_576 {
                continue;
            }
        }
        let Ok(rel) = path.strip_prefix(root) else {
            continue;
        };
        if rel.as_os_str().is_empty() {
            continue;
        }
        out.push(rel.to_path_buf());
    }
    out
}
