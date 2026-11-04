//! Cross-platform behavior: OS temp-dir defaults, path normalization,
//! and portable PoC templates.

use patchproof_core::config::{default_repo_root, normalize_local_path, Settings};
use patchproof_core::sandbox::poc_template;

#[test]
fn test_default_repo_root_uses_os_temp_dir() {
    let root = default_repo_root();
    let tmp = std::env::temp_dir().to_string_lossy().to_string();
    assert!(root.starts_with(&tmp), "{root} not under {tmp}");
    assert!(root.contains("patchproof"), "{root}");
    assert_eq!(Settings::default().repo_root, root);
}

#[test]
fn test_normalize_local_path() {
    assert_eq!(
        normalize_local_path("fixtures/vuln-app"),
        "fixtures/vuln-app"
    );
    assert_eq!(
        normalize_local_path("file://fixtures/vuln-app"),
        "fixtures/vuln-app"
    );
    assert_eq!(normalize_local_path("/srv/data/repo"), "/srv/data/repo");
    assert_eq!(normalize_local_path("C:/src/repo"), "C:/src/repo");
    assert_eq!(normalize_local_path("/C:/src/repo"), "C:/src/repo");
    assert_eq!(normalize_local_path("file:///C:/src/repo"), "C:/src/repo");
    assert_eq!(
        normalize_local_path("  fixtures/vuln-app  "),
        "fixtures/vuln-app"
    );
    assert_eq!(
        normalize_local_path("file://file://fixtures/vuln-app"),
        "fixtures/vuln-app"
    );
}

#[test]
fn test_poc_templates_portable() {
    // Every template keeps the REPRODUCED marker contract ...
    for rule in [
        "PY-SQLI-001",
        "PY-CMDI-001",
        "PY-XSS-001",
        "PY-PATHTRAV-001",
        "PY-DESER-001",
        "PY-SECRET-001",
        "PY-SSRF-001",
    ] {
        assert!(poc_template(rule).contains("REPRODUCED"), "{rule}");
    }
    // ... and the CMDI template must not depend on a shell `echo`
    // binary, which does not exist on Windows.
    let cmdi = poc_template("PY-CMDI-001");
    assert!(cmdi.contains("sys.executable"), "{cmdi}");
    assert!(!cmdi.contains("shell=True"), "{cmdi}");
}

#[test]
fn test_find_python_returns_working_interpreter() {
    // Whatever this machine has (real Python, a broken redirect stub, or
    // nothing), find_python must only return interpreters that actually run.
    if let Some(py) = patchproof_core::sandbox::find_python() {
        let status = std::process::Command::new(&py)
            .args([
                "-c",
                "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)",
            ])
            .stdin(std::process::Stdio::null())
            .stdout(std::process::Stdio::null())
            .stderr(std::process::Stdio::null())
            .status()
            .expect("returned interpreter must spawn");
        assert!(status.success(), "{py} failed its own probe");
    }
}
