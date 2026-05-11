#[derive(Debug, Clone)]
pub enum ScanProgress {
    Started { total: Option<usize> },
    File { path: String, matched: usize },
    Completed { files_scanned: usize, candidates: usize },
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, PartialOrd, Ord)]
pub struct NoiseScore(pub u32);
