//! Walk a repo checkout and persist findings (ports
//! `backend/app/scanner/scan.py`).

use std::path::Path;

use crate::error::Result;
use crate::model::Finding;
use crate::store::Store;

use super::rules::scan_source;

pub const SKIP_DIRS: &[&str] = &[".git", ".venv", "venv", "__pycache__", "node_modules", ".tox"];

/// Scan every `*.py` file under `repo_path`, skipping vendored directories.
pub fn scan_repo(store: &Store, scan_id: &str, repo_path: &str) -> Result<Vec<Finding>> {
    let root = Path::new(repo_path);
    let mut files = Vec::new();
    for entry in walkdir::WalkDir::new(root)
        .into_iter()
        .filter_entry(|e| {
            if e.depth() > 0 && e.file_type().is_dir() {
                let name = e.file_name().to_string_lossy();
                if SKIP_DIRS.iter().any(|s| *s == name) {
                    return false;
                }
            }
            true
        })
        .filter_map(|e| e.ok())
    {
        let path = entry.path();
        if path.is_file() && path.extension().map(|x| x == "py").unwrap_or(false) {
            files.push(path.to_path_buf());
        }
    }
    files.sort();

    let mut created = Vec::new();
    for path in files {
        let bytes = match std::fs::read(&path) {
            Ok(b) => b,
            Err(_) => continue,
        };
        let source = String::from_utf8_lossy(&bytes);
        let rel = path
            .strip_prefix(root)
            .map(|p| p.to_string_lossy().to_string())
            .unwrap_or_else(|_| path.to_string_lossy().to_string());
        for raw in scan_source(&source) {
            let finding = store.create_finding(scan_id, &raw, &rel)?;
            created.push(finding);
        }
    }
    store.add_evidence(
        scan_id,
        "scan",
        "detector",
        &format!("Static scan complete: {} raw findings", created.len()),
        "",
    )?;
    Ok(created)
}
