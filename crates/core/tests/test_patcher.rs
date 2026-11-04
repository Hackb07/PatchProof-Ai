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

fn write_repo(dir: &Path, name: &str, content: &str) -> String {
    let repo = dir.join(name);
    std::fs::create_dir_all(&repo).unwrap();
    std::fs::write(repo.join("app.py"), content).unwrap();
    repo.to_string_lossy().to_string()
}

#[test]
fn test_sequential_patches_same_checkout_all_land() {
    // Regression test: diffs generated against the original file must all
    // apply to ONE checkout (the verifier's flow), each landing on its own
    // sink even as earlier patches shift line numbers.
    let tmp = tempfile::tempdir().unwrap();
    let repo = tmp.path().join("repo");
    copy_dir(&fixture_repo(), &repo);
    let repo_s = repo.to_string_lossy().to_string();
    let source = std::fs::read_to_string(repo.join("app.py")).unwrap();
    let raws = scan_source(&source);
    assert!(raws.len() >= 7, "raws: {raws:?}");

    let mut diffs = Vec::new();
    for raw in &raws {
        let (diff, _summary) =
            deterministic_fix(&repo_s, "app.py", raw.line_no as i64, &raw.rule_id, "hint");
        assert!(!diff.is_empty(), "{raw:?}");
        diffs.push(diff);
    }
    for (raw, diff) in raws.iter().zip(diffs.iter()) {
        assert!(apply_diff(&repo_s, diff), "{raw:?} failed to apply");
    }
    let patched = std::fs::read_to_string(repo.join("app.py")).unwrap();
    assert_ne!(python_syntax_ok(&patched), Some(false));
    let fresh = scan_source(&patched);
    assert!(
        fresh.is_empty(),
        "sinks still flagged after all patches: {fresh:?}"
    );
}

#[test]
fn test_cmdi_multiword_command_becomes_argv() {
    let tmp = tempfile::tempdir().unwrap();
    let repo_s = write_repo(
        tmp.path(),
        "repo",
        "import subprocess\nsubprocess.run(f\"ls -la {d}\", shell=True)\n",
    );
    let (diff, _) = deterministic_fix(&repo_s, "app.py", 2, "PY-CMDI-001", "hint");
    assert!(diff.contains("[\"ls\", \"-la\", d]"), "{diff}");
    assert!(diff.contains("shell=False"), "{diff}");
    assert!(apply_diff(&repo_s, &diff));
    let patched = std::fs::read_to_string(Path::new(&repo_s).join("app.py")).unwrap();
    assert!(!scan_source(&patched)
        .iter()
        .any(|f| f.rule_id == "PY-CMDI-001"));
}

#[test]
fn test_cmdi_string_without_argv_gets_advisory_only() {
    // A bare shell flip on a plain string would break the call; the patcher
    // must not claim a real fix there.
    let tmp = tempfile::tempdir().unwrap();
    let repo_s = write_repo(
        tmp.path(),
        "repo",
        "import subprocess\nsubprocess.run(\"ls -la\", shell=True)\n",
    );
    let (diff, summary) = deterministic_fix(&repo_s, "app.py", 2, "PY-CMDI-001", "hint");
    assert!(summary.starts_with("Advisory"), "{summary}\n{diff}");
}

#[test]
fn test_sqli_double_quoted_placeholder_and_comment_paren() {
    let tmp = tempfile::tempdir().unwrap();
    let repo_s = write_repo(
        tmp.path(),
        "repo",
        "cursor.execute(f'SELECT * FROM t WHERE a = \"{v}\"')  # foo()\n",
    );
    let (diff, _) = deterministic_fix(&repo_s, "app.py", 1, "PY-SQLI-001", "hint");
    assert!(diff.contains("= ?', (v,))  # foo()"), "{diff}");
    assert!(!diff.contains("\"?\""), "{diff}");
}

#[test]
fn test_from_import_does_not_satisfy_need_import() {
    let tmp = tempfile::tempdir().unwrap();
    let repo_s = write_repo(
        tmp.path(),
        "repo",
        "from html import escape\nrender_template_string(\"<h1>\" + name + \"</h1>\")\n",
    );
    let (diff, _) = deterministic_fix(&repo_s, "app.py", 2, "PY-XSS-001", "hint");
    assert!(diff.contains("+import html"), "{diff}");
}

#[test]
fn test_pickle_load_fixed_like_loads() {
    let tmp = tempfile::tempdir().unwrap();
    let repo_s = write_repo(tmp.path(), "repo", "import pickle\ndata = pickle.load(f)\n");
    let (diff, _) = deterministic_fix(&repo_s, "app.py", 2, "PY-DESER-001", "hint");
    assert!(diff.contains("json.load(f)"), "{diff}");
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
        let trial = tmp
            .path()
            .join(format!("trial-{}-{}", raw.rule_id, raw.line_no));
        copy_dir(&fixture_repo(), &trial);
        let trial_s = trial.to_string_lossy().to_string();
        let (diff, _summary) =
            deterministic_fix(&trial_s, "app.py", raw.line_no as i64, &raw.rule_id, "hint");
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
