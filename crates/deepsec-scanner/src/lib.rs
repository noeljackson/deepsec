//! deepsec-scanner: file walking, tech detection, and matcher engine.
//!
//! Matchers are loaded from TOML rather than TypeScript modules. The
//! bundled matcher pack lives under `matchers/` at the workspace root
//! and is embedded into the binary via `include_dir!`. Users can
//! extend the pack via `[matchers].extra_paths` in their config.

pub mod detect;
pub mod gate;
pub mod matchers;
pub mod registry;
pub mod scan;
pub mod types;
pub mod walker;

pub use detect::{DetectedTech, detect_tech, read_tech_json, write_tech_json};
pub use gate::evaluate_gate;
pub use matchers::{
    Matcher, MatcherDef, MatcherGate, NoiseTier, load_matcher_toml, load_matchers_from_dir,
    parse_matcher_toml, BUILTIN_MATCHERS,
};
pub use registry::MatcherRegistry;
pub use scan::{
    LanguageStat, ScanOptions, ScanOutcome, ScanFilesOutcome, batch_candidates, scan,
    scan_files,
};
pub use types::{NoiseScore, ScanProgress};
pub use walker::{IGNORE_DIRS, walk_project};
