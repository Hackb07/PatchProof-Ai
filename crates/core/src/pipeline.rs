//! Planner agent: orchestrates scan -> triage -> risk -> repro ->
//! validate -> patch -> verify (ports `backend/app/agents/planner.py`).

use std::path::Path;

use crate::agents::llm::LlmClient;
use crate::config::Settings;
use crate::error::{CoreError, Result};
use crate::store::Store;
use crate::truncate_chars;

/// Run the full pipeline for a scan. Never fails outward: errors mark the
/// scan `failed` with a truncated message, like the Python version.
pub async fn run_pipeline(store: Store, settings: Settings, scan_id: String) {
    if matches!(store.get_scan(&scan_id), Ok(None) | Err(_)) {
        return;
    }
    let result = run_inner(&store, &settings, &scan_id).await;
    if let Err(e) = result {
        let msg = e.to_string();
        let _ = store.set_scan_failed(&scan_id, &truncate_chars(&msg, 2000));
        let _ = store.add_evidence(
            &scan_id,
            "done",
            "planner",
            &format!("Pipeline failed: {e}"),
            "",
        );
    }
}

async fn run_inner(store: &Store, settings: &Settings, scan_id: &str) -> Result<()> {
    store.update_scan_status(scan_id, "scanning")?;

    let repo_path = prepare_repo(store, settings, scan_id).await?;
    crate::scanner::scan::scan_repo(store, scan_id, &repo_path)?;

    store.update_scan_status(scan_id, "triaging")?;
    let llm = LlmClient::new(settings);
    crate::agents::detector::triage(store, &llm, scan_id).await?;
    crate::agents::risk::assess(store, &llm, scan_id).await?;

    store.update_scan_status(scan_id, "patching")?;
    crate::sandbox::reproduce(store, settings, scan_id).await?;
    crate::agents::validator::validate(store, &llm, scan_id).await?;
    crate::patcher::generator::generate_patches(store, &llm, scan_id, &repo_path).await?;

    store.update_scan_status(scan_id, "verifying")?;
    crate::verifier::verify_patches(store, scan_id, &repo_path).await?;

    store.set_scan_done(scan_id)?;
    store.add_evidence(
        scan_id,
        "done",
        "planner",
        "Pipeline complete: scan, triage, risk, repro, patch, verify",
        "",
    )?;
    Ok(())
}

async fn prepare_repo(store: &Store, settings: &Settings, scan_id: &str) -> Result<String> {
    let scan = store
        .get_scan(scan_id)?
        .ok_or(CoreError::ScanNotFound)?;
    let root = Path::new(&settings.repo_root);
    std::fs::create_dir_all(root)?;
    let dest = root.join(&scan.id);
    let url = scan.repo_url.trim().to_string();
    // Local path support for fixtures/demo: file:// or plain path copies
    // instead of cloning.
    let local = url.strip_prefix("file://").unwrap_or(&url).to_string();
    if Path::new(&local).is_dir() {
        if dest.exists() {
            std::fs::remove_dir_all(&dest)?;
        }
        copy_tree(Path::new(&local), &dest)?;
        let dest_s = dest.to_string_lossy().to_string();
        store.set_scan_repo_path(scan_id, &dest_s)?;
        store.add_evidence(
            scan_id,
            "clone",
            "planner",
            &format!("Local repo copied from {local}"),
            "",
        )?;
        return Ok(dest_s);
    }
    if dest.exists() {
        std::fs::remove_dir_all(&dest)?;
    }
    let mut cmd = tokio::process::Command::new("git");
    cmd.arg("clone").arg("--depth").arg("1");
    if !scan.branch.is_empty() && scan.branch != "HEAD" {
        cmd.arg("--branch").arg(&scan.branch);
    }
    cmd.arg(&url).arg(&dest);
    let output = cmd
        .output()
        .await
        .map_err(|e| CoreError::Repo(format!("git clone failed: {e}")))?;
    if !output.status.success() {
        let stderr = String::from_utf8_lossy(&output.stderr);
        return Err(CoreError::Repo(format!(
            "git clone failed: {}",
            stderr.trim()
        )));
    }
    let dest_s = dest.to_string_lossy().to_string();
    store.set_scan_repo_path(scan_id, &dest_s)?;
    store.add_evidence(
        scan_id,
        "clone",
        "planner",
        &format!("Cloned {} ({})", url, scan.branch),
        "",
    )?;
    Ok(dest_s)
}

const COPY_IGNORE: &[&str] = &[".git", "__pycache__", ".venv"];

fn copy_tree(src: &Path, dest: &Path) -> Result<()> {
    std::fs::create_dir_all(dest)?;
    for entry in walkdir::WalkDir::new(src)
        .into_iter()
        .filter_entry(|e| {
            if e.depth() > 0 {
                let name = e.file_name().to_string_lossy();
                if COPY_IGNORE.iter().any(|s| *s == name) {
                    return false;
                }
            }
            true
        })
        .filter_map(|e| e.ok())
    {
        let rel = match entry.path().strip_prefix(src) {
            Ok(r) => r,
            Err(_) => continue,
        };
        if rel.as_os_str().is_empty() {
            continue;
        }
        let target = dest.join(rel);
        if entry.file_type().is_dir() {
            std::fs::create_dir_all(&target)?;
        } else if entry.path().is_file() {
            if let Some(parent) = target.parent() {
                std::fs::create_dir_all(parent)?;
            }
            std::fs::copy(entry.path(), &target)?;
        }
    }
    Ok(())
}
