use deepsec_core::FileRecord;
use std::collections::BTreeMap;
use std::path::Path;

/// Group records into directory-coherent batches, splitting large
/// directories and merging small ones. Mirrors the TS heuristic.
pub fn batch_records<'a>(records: &'a [FileRecord], max_batch: usize) -> Vec<Vec<&'a FileRecord>> {
    let mut by_dir: BTreeMap<String, Vec<&FileRecord>> = BTreeMap::new();
    for r in records {
        let dir = Path::new(&r.file_path)
            .parent()
            .and_then(|p| p.to_str())
            .unwrap_or("")
            .to_string();
        by_dir.entry(dir).or_default().push(r);
    }
    let mut out: Vec<Vec<&FileRecord>> = Vec::new();
    let mut current: Vec<&FileRecord> = Vec::new();
    for (_dir, files) in by_dir {
        for chunk in files.chunks(max_batch) {
            if current.len() + chunk.len() <= max_batch {
                current.extend(chunk);
            } else {
                if !current.is_empty() {
                    out.push(std::mem::take(&mut current));
                }
                out.push(chunk.to_vec());
            }
        }
    }
    if !current.is_empty() {
        out.push(current);
    }
    out
}
