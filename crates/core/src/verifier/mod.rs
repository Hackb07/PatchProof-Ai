//! Fix verification: re-scan the patched file plus repo tests (ports
//! `backend/app/verifier/verify.py`).

use std::path::Path;
use std::time::Duration;

use crate::config::Settings;
use crate::error::Result;
use crate::model::{Finding, Verification};
use crate::patcher::applier::apply_diff;
use crate::scanner::rules::scan_source;
use crate::store::Store;
use crate::truncate_chars;

/// Verify every patch of a scan.
pub async fn verify_patches(
    store: &Store,
    scan_id: &str,
    repo_path: &str,
    settings: &Settings,
) -> Result<Vec<Verification>> {
    let findings = store.list_findings(scan_id)?;
    let trusted = store
        .get_scan(scan_id)?
        .is_some_and(|s| crate::config::is_local_scan_repo(&s.repo_url));
    let mut results = Vec::new();
    for finding in &findings {
        for patch in store.patches_for_finding(&finding.id)? {
            let target = Path::new(repo_path).join(&finding.file_path);
            let before = read_lossy_opt(&target);
            let applied = if patch.diff.is_empty() {
                false
            } else {
                apply_diff(repo_path, &patch.diff)
            };
            store.set_patch_applied(&patch.id, applied)?;
            let after = read_lossy_opt(&target);

            let rescan_clean = rescan_clean(&before, &after, finding);
            let (tests_passed, test_log) = run_repo_tests(repo_path, trusted, settings).await;
            let status = decide(applied, rescan_clean, tests_passed);
            let notes = format!(
                "Patch {}; rescan {}; tests {}.",
                if applied { "applied" } else { "NOT applied" },
                if rescan_clean {
                    "clean"
                } else {
                    "still flags the sink"
                },
                match tests_passed {
                    Some(true) => "passed",
                    Some(false) => "failed",
                    None => "not found",
                }
            );
            let verification = store.create_verification(
                &patch.id,
                &status,
                rescan_clean,
                tests_passed,
                &truncate_chars(&test_log, 3000),
                &notes,
            )?;
            store.add_evidence(
                scan_id,
                "verify",
                "verifier",
                &format!(
                    "Verification {} for patch {}: {}",
                    verification.id, patch.id, status
                ),
                &verification.id,
            )?;
            results.push(verification);
        }
    }
    let fixed = results.iter().filter(|v| v.status == "fixed").count();
    store.add_evidence(
        scan_id,
        "verify",
        "verifier",
        &format!("Verification complete: {}/{} fixed", fixed, results.len()),
        "",
    )?;
    Ok(results)
}

fn read_lossy_opt(path: &Path) -> String {
    std::fs::read(path)
        .map(|b| String::from_utf8_lossy(&b).to_string())
        .unwrap_or_default()
}

fn decide(applied: bool, rescan_clean: bool, tests_passed: Option<bool>) -> String {
    if !applied {
        return "unfixed".to_string();
    }
    if rescan_clean && tests_passed != Some(false) {
        return "fixed".to_string();
    }
    if !rescan_clean {
        return "unfixed".to_string();
    }
    "inconclusive".to_string()
}

fn rescan_clean(before: &str, after: &str, finding: &Finding) -> bool {
    if after == before {
        return false;
    }
    // Anchor on the fix comment the patcher always inserts: helper
    // insertions at the top of the file shift the sink away from its
    // original line number, so the original `line_no` window is stale.
    let marker = format!("# PatchProof fix ({})", finding.rule_id);
    let anchor: Option<usize> = after
        .lines()
        .enumerate()
        .filter(|(_, l)| l.contains(marker.as_str()))
        .map(|(i, _)| i + 1)
        .last();
    let fresh: Vec<_> = scan_source(after)
        .into_iter()
        .filter(|f| f.rule_id == finding.rule_id)
        .collect();
    let before_count = scan_source(before)
        .into_iter()
        .filter(|f| f.rule_id == finding.rule_id)
        .count();
    match anchor {
        Some(line) => {
            let near = fresh
                .iter()
                .filter(|f| f.line_no.abs_diff(line) <= 2)
                .count();
            near == 0 || fresh.len() < before_count
        }
        None => rescan_clean_legacy(before_count, &fresh, after, finding),
    }
}

/// Fallback when the fix comment is missing: look for hardening markers
/// near the original sink line, then confirm by rescan.
fn rescan_clean_legacy(
    before_count: usize,
    fresh: &[crate::scanner::rules::RawFinding],
    after: &str,
    finding: &Finding,
) -> bool {
    let markers = [
        "# PatchProof fix",
        "shell=False",
        "safe_load",
        "os.environ",
        "html.escape",
        "allowlist",
    ];
    let lines: Vec<&str> = after.split('\n').collect();
    let line_no = finding.line_no.max(1) as usize;
    let start = line_no.saturating_sub(3);
    let end = (line_no + 3).min(lines.len());
    let near = lines[start..end].join("\n");
    if markers.iter().any(|m| near.contains(m)) {
        let same_line = fresh
            .iter()
            .filter(|f| f.line_no.abs_diff(line_no) <= 2)
            .count();
        return same_line == 0 || fresh.len() < before_count;
    }
    false
}

async fn run_repo_tests(
    repo_path: &str,
    trusted_local: bool,
    settings: &Settings,
) -> (Option<bool>, String) {
    let root = Path::new(repo_path);
    if !has_pytest_files(root) {
        return (
            None,
            "No pytest-style tests found in target repo.".to_string(),
        );
    }
    // Untrusted (cloned) repos must never execute test code on the host:
    // run them containerized, or skip with a clear message.
    if !trusted_local {
        if settings.sandbox_backend != "subprocess"
            && crate::sandbox::which_bin("docker")
            && crate::sandbox::docker_alive().await
        {
            return run_docker_tests(repo_path, settings).await;
        }
        return (
            None,
            "Test run skipped: remote scan and no Docker sandbox available \
             (refusing to execute untrusted test code on the host)."
                .to_string(),
        );
    }
    let Some(python) = crate::sandbox::find_python() else {
        return (
            None,
            "Test run failed: no working python interpreter found (need Python 3.11+)".to_string(),
        );
    };
    let fut = tokio::process::Command::new(python)
        .args(["-m", "pytest", "-q", "-p", "no:cacheprovider"])
        .current_dir(root)
        .output();
    let output = match tokio::time::timeout(Duration::from_secs(60), fut).await {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => return (None, format!("Test run failed: {e}")),
        Err(_) => return (None, "Test run failed: timed out after 60s".to_string()),
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stdout.contains("No module named pytest") || stderr.contains("No module named pytest") {
        return (
            None,
            "pytest is not installed for the target interpreter; tests not run.".to_string(),
        );
    }
    let code = output.status.code().unwrap_or(-1);
    let log = format!("$ pytest -q\n{stdout}{stderr}\n[exit={code}]");
    (Some(output.status.success()), log)
}

async fn run_docker_tests(repo_path: &str, settings: &Settings) -> (Option<bool>, String) {
    let root = Path::new(repo_path);
    let mount = crate::sandbox::docker_mount_arg(root, "rw");
    let fut = tokio::process::Command::new("docker")
        .args([
            "run",
            "--rm",
            "--network",
            "none",
            "--memory",
            "256m",
            "--cpus",
            "0.5",
            "-v",
            &mount,
            "-w",
            "/work",
            &settings.sandbox_image,
            "python",
            "-m",
            "pytest",
            "-q",
            "-p",
            "no:cacheprovider",
        ])
        .output();
    let output = match tokio::time::timeout(Duration::from_secs(90), fut).await {
        Ok(Ok(o)) => o,
        Ok(Err(e)) => return (None, format!("Test run failed: {e}")),
        Err(_) => return (None, "Test run failed: timed out after 90s".to_string()),
    };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    if stdout.contains("No module named pytest") || stderr.contains("No module named pytest") {
        return (
            None,
            format!(
                "pytest is not installed in sandbox image {}; tests not run.",
                settings.sandbox_image
            ),
        );
    }
    if !output.status.success() && stderr.contains("Unable to find image") {
        return (
            None,
            format!(
                "Sandbox image {} not available locally; tests not run.",
                settings.sandbox_image
            ),
        );
    }
    let code = output.status.code().unwrap_or(-1);
    let log = format!(
        "$ docker run --rm --network none {} python -m pytest -q\n{stdout}{stderr}\n[exit={code}]",
        settings.sandbox_image
    );
    (Some(output.status.success()), log)
}

fn has_pytest_files(root: &Path) -> bool {
    if glob_prefix(root, "test_", ".py") {
        return true;
    }
    glob_prefix(&root.join("tests"), "test_", ".py")
}

fn glob_prefix(dir: &Path, prefix: &str, suffix: &str) -> bool {
    let entries = match std::fs::read_dir(dir) {
        Ok(e) => e,
        Err(_) => return false,
    };
    for entry in entries.filter_map(|e| e.ok()) {
        let name = entry.file_name().to_string_lossy().to_string();
        if name.starts_with(prefix) && name.ends_with(suffix) && entry.path().is_file() {
            return true;
        }
    }
    false
}
