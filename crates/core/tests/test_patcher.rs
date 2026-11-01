//! Patcher round-trip: deterministic fixes apply and rescan clean (ports
//! `backend/tests/test_patcher.py`).

use std::path::{Path, PathBuf};

use patchproof_core::patcher::applier::apply_diff;
use patchproof_core::patcher::generator::{deterministic_fix, python_syntax_ok};
use patchproof_core::scanner::rules::scan_source;

fn fixture_repo() -> PathBuf {
    Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/vuln-app")
}

fn copy_dir(src: &Path, dest: &Path) {
    std::fs::create_dir_all(dest).unwrap();
    for entry in walkdir::WalkDir::new(src)
        .into_iter()
        .filter_map(|e| e.ok())
    {
        let rel = entry.path().strip_prefix(src).unwrap();
        if rel.as_os_str().is_empty() {
            continue;
        }
        let target = dest.join(rel);
        if entry.file_type().is_dir() {
            std::fs::create_dir_all(&target).unwrap();
        } else {
            std::fs::copy(entry.path(), &target).unwrap();
        }
    }
}

#[test]
fn test_fixture_patches_apply_and_rescan_clean() {
    // walkdir is a main dependency of the core crate; reuse it via a thin
    // local copy helper instead of adding a dev-dependency.
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("repo");
    copy_dir(&fixture_repo(), &repo);
    let source = std::fs::read_to_string(repo.join("app.py")).unwrap();
    let raws = scan_source(&source);
    assert!(raws.len() >= 7, "raws: {raws:?}");

    // Apply one finding at a time on fresh copies (line numbers stay valid).
    for raw in &raws {
        let trial = tmp.path().join(format!("trial-{}-{}", raw.rule_id, raw.line_no));
        copy_dir(&fixture_repo(), &trial);
        let trial_s = trial.to_string_lossy().to_string();
        let (diff, _summary) = deterministic_fix(
            &trial_s,
            "app.py",
            raw.line_no as i64,
            &raw.rule_id,
            "hint",
        );
        assert!(!diff.is_empty(), "{raw:?}");
        assert!(apply_diff(&trial_s, &diff), "{raw:?}");
        let patched = std::fs::read_to_string(trial.join("app.py")).unwrap();
        // Must stay syntactically valid (skipped when no interpreter exists).
        assert_ne!(python_syntax_ok(&patched), Some(false), "{raw:?}");
        let fresh: Vec<_> = scan_source(&patched)
            .into_iter()
            .filter(|f| f.rule_id == raw.rule_id)
            .collect();
        let near: Vec<_> = fresh
            .iter()
            .filter(|f| f.line_no.abs_diff(raw.line_no) <= 4)
            .collect();
        assert!(
            near.is_empty(),
            "{raw:?} still flagged at {:?}",
            fresh.iter().map(|f| f.line_no).collect::<Vec<_>>()
        );
    }
}
