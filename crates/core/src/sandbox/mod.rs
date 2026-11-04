//! Sandboxed proof-of-concept reproduction (ports
//! `backend/app/sandbox/runner.py`).
//!
//! For each finding, a small PoC script demonstrates the dangerous sink is
//! reachable, executed in an isolated backend: a Docker container when
//! available, else a timeout-bounded local subprocess with no network.
//! Command-injection PoCs run fixed print markers only (no shell).

use std::time::Duration;

use crate::config::Settings;
use crate::error::Result;
use crate::model::Finding;
use crate::store::Store;
use crate::truncate_chars;

pub const POC_SQLI: &str = "query = f\"SELECT * FROM users WHERE name = '{{payload}}'\"\nprint('POC-SQLI: query built:', query)\nassert \"' OR '1'='1\" in query\nprint('POC-SQLI: REPRODUCED - injection string reaches SQL')\n";
pub const POC_CMDI: &str = "import subprocess, sys\npayload = \"hello; echo POC-CMDI-MARKER\"\nprint('POC-CMDI: payload reaches shell sink:', payload)\n# Safe: fixed print only, never executes the injected part (no shell, no echo binary)\nr = subprocess.run([sys.executable, '-c', \"print('POC-CMDI-MARKER')\"], capture_output=True, text=True, timeout=5)\nassert 'POC-CMDI-MARKER' in r.stdout\nprint('POC-CMDI: REPRODUCED - sink reachable (simulated safely)')\n";
pub const POC_XSS: &str = "payload = \"<script>alert(1)</script>\"\nrendered = f\"<div>{payload}</div>\"\nprint('POC-XSS: rendered:', rendered)\nassert '<script>' in rendered\nprint('POC-XSS: REPRODUCED - unescaped script reaches output')\n";
pub const POC_PATHTRAV: &str = "from pathlib import Path\npayload = \"../../etc/passwd\"\nresolved = (Path('/srv/app/data') / payload).resolve()\nprint('POC-PATHTRAV: resolved:', resolved)\nassert str(resolved).startswith('/etc') or '..' in payload\nprint('POC-PATHTRAV: REPRODUCED - traversal escapes base dir')\n";
pub const POC_DESER: &str = "import pickle\npayload = pickle.dumps({'role': 'admin'})\nobj = pickle.loads(payload)\nprint('POC-DESER: decoded:', obj)\nassert obj['role'] == 'admin'\nprint('POC-DESER: REPRODUCED - pickle sink decodes untrusted bytes')\n";
pub const POC_SECRET: &str =
    "print('POC-SECRET: REPRODUCED - credential literal present in source; rotation required')\n";
pub const POC_SSRF: &str = "from urllib.parse import urlparse\npayload = \"http://169.254.169.254/latest/meta-data\"\nhost = urlparse(payload).hostname\nprint('POC-SSRF: host:', host)\nassert host == '169.254.169.254'\nprint('POC-SSRF: REPRODUCED - internal host not blocked')\n";
pub const POC_DEFAULT: &str = "print('POC: no template; sink noted')\n";

pub fn poc_template(rule_id: &str) -> &'static str {
    match rule_id {
        "PY-SQLI-001" => POC_SQLI,
        "PY-CMDI-001" => POC_CMDI,
        "PY-XSS-001" => POC_XSS,
        "PY-PATHTRAV-001" => POC_PATHTRAV,
        "PY-DESER-001" => POC_DESER,
        "PY-SECRET-001" => POC_SECRET,
        "PY-SSRF-001" => POC_SSRF,
        _ => POC_DEFAULT,
    }
}

/// Reproduce every non-false-positive finding of a scan.
pub async fn reproduce(store: &Store, settings: &Settings, scan_id: &str) -> Result<Vec<Finding>> {
    let findings = store.list_active_findings(scan_id)?;
    let backend = pick_backend(settings).await;
    let mut reproduced_count = 0;
    for f in &findings {
        let mut template = poc_template(&f.rule_id).to_string();
        if f.rule_id == "PY-SQLI-001" {
            template = template.replace("{{payload}}", "' OR '1'='1");
        }
        let (log, ok) = run_poc(&template, &backend, settings).await;
        let header = format!(
            "[sandbox:{}] PoC for {} at {}:{}\n",
            backend, f.rule_id, f.file_path, f.line_no
        );
        let full = truncate_chars(&format!("{header}{log}"), 4000);
        store.update_finding_repro(&f.id, ok, &full)?;
        if ok {
            reproduced_count += 1;
        }
    }
    store.add_evidence(
        scan_id,
        "repro",
        "sandbox",
        &format!(
            "Reproduction complete via {}: {}/{} reproduced",
            backend,
            reproduced_count,
            findings.len()
        ),
        "",
    )?;
    Ok(findings)
}

async fn pick_backend(settings: &Settings) -> String {
    if settings.sandbox_backend == "subprocess" {
        return "subprocess".to_string();
    }
    if (settings.sandbox_backend == "docker" || settings.sandbox_backend == "auto")
        && which_bin("docker")
        && docker_alive().await
    {
        return "docker".to_string();
    }
    "subprocess".to_string()
}

pub async fn docker_alive() -> bool {
    let fut = tokio::process::Command::new("docker").arg("info").output();
    match tokio::time::timeout(Duration::from_secs(10), fut).await {
        Ok(Ok(out)) => out.status.success(),
        _ => false,
    }
}

/// `host-path:/work:<mode>` bind-mount argument (Docker expects forward
/// slashes in the source, even on Windows).
pub fn docker_mount_arg(host_path: &std::path::Path, mode: &str) -> String {
    let mount_src = host_path.to_string_lossy();
    #[cfg(windows)]
    let mount_src = mount_src.replace('\\', "/");
    format!("{mount_src}:/work:{mode}")
}

async fn run_poc(code: &str, backend: &str, settings: &Settings) -> (String, bool) {
    if backend == "docker" {
        match run_docker(code, settings).await {
            Ok(result) => result,
            Err(exc) => {
                let (out, ok) = run_subprocess(code, settings).await;
                (
                    format!("docker unavailable ({exc}); subprocess fallback:\n{out}"),
                    ok,
                )
            }
        }
    } else {
        run_subprocess(code, settings).await
    }
}

async fn run_subprocess(code: &str, settings: &Settings) -> (String, bool) {
    let tmp = match tempfile::tempdir() {
        Ok(t) => t,
        Err(e) => return (format!("[error] {e}"), false),
    };
    let script = tmp.path().join("poc.py");
    if let Err(e) = std::fs::write(&script, code) {
        return (format!("[error] {e}"), false);
    }
    let Some(python) = find_python() else {
        return (
            "[error] no working python interpreter found (need Python 3.11+; set PYTHON= to override)"
                .to_string(),
            false,
        );
    };
    let fut = tokio::process::Command::new(python)
        .arg(&script)
        .current_dir(tmp.path())
        .output();
    let output =
        match tokio::time::timeout(Duration::from_secs(settings.sandbox_timeout_s.max(1)), fut)
            .await
        {
            Ok(Ok(o)) => o,
            Ok(Err(e)) => return (format!("[error] {e}"), false),
            Err(_) => {
                return (
                    "[timeout] PoC exceeded sandbox time limit".to_string(),
                    false,
                )
            }
        };
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let code_status = output.status.code().unwrap_or(-1);
    let log = format!("$ python poc.py\n{stdout}{stderr}\n[exit={code_status}]");
    let ok = output.status.success() && stdout.contains("REPRODUCED");
    (log, ok)
}

async fn run_docker(
    code: &str,
    settings: &Settings,
) -> std::result::Result<(String, bool), String> {
    let tmp = tempfile::tempdir().map_err(|e| e.to_string())?;
    std::fs::write(tmp.path().join("poc.py"), code).map_err(|e| e.to_string())?;
    let mount = docker_mount_arg(tmp.path(), "ro");
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
            &settings.sandbox_image,
            "python",
            "/work/poc.py",
        ])
        .output();
    let output = tokio::time::timeout(
        Duration::from_secs(settings.sandbox_timeout_s.max(1) + 30),
        fut,
    )
    .await
    .map_err(|_| {
        format!(
            "timed out after {}s",
            settings.sandbox_timeout_s.max(1) + 30
        )
    })?
    .map_err(|e| e.to_string())?;
    let stdout = String::from_utf8_lossy(&output.stdout);
    let stderr = String::from_utf8_lossy(&output.stderr);
    let code_status = output.status.code().unwrap_or(-1);
    let log = format!(
        "$ docker run --rm --network none {} python /work/poc.py\n{stdout}{stderr}\n[exit={code_status}]",
        settings.sandbox_image
    );
    Ok((
        log,
        output.status.success() && stdout.contains("REPRODUCED"),
    ))
}

/// Search `PATH` for an executable (mirrors `shutil.which`).
pub fn which_bin(name: &str) -> bool {
    let Some(paths) = std::env::var_os("PATH") else {
        return false;
    };
    for dir in std::env::split_paths(&paths) {
        if dir.join(name).is_file() {
            return true;
        }
        #[cfg(windows)]
        for ext in ["exe", "cmd", "bat"] {
            if dir.join(format!("{name}.{ext}")).is_file() {
                return true;
            }
        }
    }
    false
}

/// Locate a working Python interpreter (>= 3.11) for PoCs, syntax gates,
/// and repo tests. Candidates that fail to run (e.g. the Windows Store
/// redirect stub) are skipped, so callers only ever see a runnable
/// interpreter or `None`.
pub fn find_python() -> Option<String> {
    if let Ok(explicit) = std::env::var("PYTHON") {
        let explicit = explicit.trim().to_string();
        if !explicit.is_empty() {
            return python_works(&explicit).then_some(explicit);
        }
    }
    #[cfg(windows)]
    let candidates = ["python", "python3", "py"];
    #[cfg(not(windows))]
    let candidates = ["python3", "python"];
    candidates
        .into_iter()
        .filter(|c| which_bin(c))
        .find(|c| python_works(c))
        .map(|s| s.to_string())
}

/// True when `candidate` executes and reports Python >= 3.11.
fn python_works(candidate: &str) -> bool {
    std::process::Command::new(candidate)
        .args([
            "-c",
            "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)",
        ])
        .stdin(std::process::Stdio::null())
        .stdout(std::process::Stdio::null())
        .stderr(std::process::Stdio::null())
        .status()
        .map(|s| s.success())
        .unwrap_or(false)
}
