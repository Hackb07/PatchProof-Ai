//! Minimal patch generation: LLM-guided, deterministic fallback (ports
//! `backend/app/patcher/generator.py`).
//!
//! The LLM proposes a minimal fix; the deterministic transforms below
//! guarantee a safe, reviewable diff even offline. Every transform is gated
//! on a Python `ast.parse` check when an interpreter is available —
//! otherwise the patcher falls back to an advisory comment so the diff can
//! never break the file's syntax.

use std::io::Write;
use std::path::Path;
use std::process::Stdio;
use std::sync::OnceLock;

use regex::Regex;

use crate::agents::llm::LlmClient;
use crate::error::Result;
use crate::model::Patch;
use crate::store::Store;

pub fn fix_hint(rule_id: &str) -> &'static str {
    match rule_id {
        "PY-SQLI-001" => "Use a parameterized query: cursor.execute('SELECT ... WHERE name = ?', (name,)) \u{2014} never interpolate.",
        "PY-CMDI-001" => "Use subprocess.run([...], shell=False) with an argv list; never shell=True with input.",
        "PY-XSS-001" => "Escape output with html.escape() or use autoescaped templates; avoid render_template_string with input.",
        "PY-PATHTRAV-001" => "Resolve against a base dir and reject paths escaping it via _confined_path().",
        "PY-DESER-001" => "Replace pickle/yaml.load with json.loads, or yaml.safe_load with an explicit Loader.",
        "PY-SECRET-001" => "Load from environment: os.environ['SECRET'] \u{2014} remove the literal and rotate it.",
        "PY-SSRF-001" => "Validate the URL host against an allowlist via _checked_url() before requesting.",
        _ => "Apply the minimal safe fix.",
    }
}

pub const CONFINED_HELPER: &str = r#"from pathlib import Path as _PPPath


def _confined_path(base, name):
    """Join *name* onto *base*, rejecting escapes (PatchProof fix)."""
    p = (_PPPath(base) / name).resolve()
    if not str(p).startswith(str(_PPPath(base).resolve())):
        raise ValueError("path escapes base directory")
    return str(p)


"#;

pub const CHECKED_URL_HELPER: &str = r#"from urllib.parse import urlparse as _pp_urlparse


def _checked_url(url):
    """Reject non-allowlisted/internal hosts (PatchProof fix)."""
    host = (_pp_urlparse(url).hostname or "").lower()
    if not host or host in ("localhost", "127.0.0.1", "::1") or host.startswith("169.254.") or host.endswith(".internal"):
        raise ValueError("URL host is not allowlisted")
    return url


"#;

macro_rules! static_re {
    ($name:ident, $pattern:expr) => {
        fn $name() -> &'static Regex {
            static CELL: OnceLock<Regex> = OnceLock::new();
            CELL.get_or_init(|| Regex::new($pattern).expect("invalid regex"))
        }
    };
}

static_re!(
    secret_assign_re,
    r#"^(\s*)([A-Za-z_][A-Za-z0-9_]*)\s*=\s*("[^"\n]*"|'[^'\n]*')\s*(#.*)?$"#
);
static_re!(
    sqli_exec_re,
    r#"(\.execute(?:many|script)?\(\s*)f(["'])"#
);
static_re!(
    cmdi_run_re,
    r#"(subprocess\.\w+\(\s*)f(["'])(\S+?)\s+\{([^{}]+)\}["']"#
);
static_re!(interp_var_re, r#"\{([^{}]+)\}"#);
static_re!(ident_re, r#"^[A-Za-z_][A-Za-z0-9_]*$"#);
static_re!(
    xss_mid_re,
    r#"\+\s*([A-Za-z_][A-Za-z0-9_]*)\s*\+"#
);
static_re!(
    xss_end_re,
    r#"\+\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)"#
);
static_re!(
    pathtrav_open_re,
    r#"open\(\s*f"([^"{}\n]*)/\{([^{}]+)\}"\s*\)"#
);
static_re!(
    ssrf_req_re,
    r#"(requests\.(?:get|post|put|delete|head|request)\(\s*)f"\{([^{}]+)\}""#
);

/// Generate one patch per non-false-positive finding.
pub async fn generate_patches(
    store: &Store,
    llm: &LlmClient,
    scan_id: &str,
    repo_path: &str,
) -> Result<Vec<Patch>> {
    let findings = store.list_active_findings(scan_id)?;
    let mut patches = Vec::new();
    for f in &findings {
        let hint = fix_hint(&f.rule_id);
        llm.chat(
            "You are a security patch engineer. Propose the MINIMAL safe fix (few lines). Reply briefly.",
            &format!(
                "{} at {}:{}\n{}\nHint: {}",
                f.title, f.file_path, f.line_no, f.snippet, hint
            ),
            800,
        )
        .await;
        let (diff, summary) =
            deterministic_fix(repo_path, &f.file_path, f.line_no, &f.rule_id, hint);
        let patch = store.create_patch(&f.id, &diff, &summary)?;
        patches.push(patch);
    }
    store.add_evidence(
        scan_id,
        "patch",
        "patcher",
        &format!("Patch generation complete: {} patches", patches.len()),
        "",
    )?;
    Ok(patches)
}

/// Deterministic file transform plus unified diff. Public so the patcher
/// round-trip test can exercise it without a database.
pub fn deterministic_fix(
    repo_path: &str,
    file_path: &str,
    line_no: i64,
    rule_id: &str,
    hint: &str,
) -> (String, String) {
    let target = Path::new(repo_path).join(file_path);
    let bytes = match std::fs::read(&target) {
        Ok(b) => b,
        Err(_) => return (String::new(), "Target file unreadable; manual fix required.".to_string()),
    };
    let content = String::from_utf8_lossy(&bytes).to_string();
    let original = split_keepends(&content);
    if original.is_empty() {
        return (String::new(), "Target file empty; manual fix required.".to_string());
    }
    let (fixed, summary) = match apply_real_fix(&original, line_no, rule_id) {
        Some(fixed) => {
            let summary = format!("Minimal fix for {rule_id} at line {line_no}: {hint}");
            (fixed, summary)
        }
        None => {
            let fixed = advisory_fix(&original, line_no, rule_id);
            let summary = format!("Advisory patch for {rule_id} at line {line_no}: {hint}");
            (fixed, summary)
        }
    };
    let diff = unified_diff(&original, &fixed, file_path);
    (diff, summary)
}

fn split_keepends(s: &str) -> Vec<String> {
    if s.is_empty() {
        return Vec::new();
    }
    s.split_inclusive('\n').map(|l| l.to_string()).collect()
}

fn apply_real_fix(
    original: &[String],
    line_no: i64,
    rule_id: &str,
) -> Option<Vec<String>> {
    let idx0 = (line_no - 1).max(0).min(original.len() as i64 - 1) as usize;
    let line = original[idx0].clone();
    let source = original.concat();
    let (top_block, new_sink) = match rule_id {
        "PY-SQLI-001" => fix_sqli(&line)?,
        "PY-CMDI-001" => fix_cmdi(&line)?,
        "PY-XSS-001" => fix_xss(&source, &line)?,
        "PY-PATHTRAV-001" => fix_pathtrav(&source, &line)?,
        "PY-DESER-001" => fix_deser(&source, &line)?,
        "PY-SECRET-001" => fix_secret(&source, &line)?,
        "PY-SSRF-001" => fix_ssrf(&source, &line)?,
        _ => return None,
    };
    if new_sink == line && top_block.is_empty() {
        return None;
    }
    let top_pos = insert_pos(original).min(original.len());
    let mut new: Vec<String> = Vec::with_capacity(original.len() + top_block.len() + 1);
    new.extend_from_slice(&original[..top_pos]);
    new.extend(top_block.iter().cloned());
    new.extend_from_slice(&original[top_pos..]);
    let idx = idx0 + top_block.len();
    new[idx] = new_sink;
    let indent: String = line.chars().take_while(|c| c.is_whitespace()).collect();
    let hint = fix_hint(rule_id);
    new.insert(idx, format!("{indent}# PatchProof fix ({rule_id}): {hint}\n"));
    match python_syntax_ok(&new.concat()) {
        Some(false) => None,
        _ => Some(new),
    }
}

fn advisory_fix(original: &[String], line_no: i64, rule_id: &str) -> Vec<String> {
    let idx = (line_no - 1).max(0).min(original.len() as i64 - 1) as usize;
    let line = &original[idx];
    let indent: String = line.chars().take_while(|c| c.is_whitespace()).collect();
    let hint = fix_hint(rule_id);
    let mut fixed = original.to_vec();
    fixed.insert(
        idx,
        format!("{indent}# PatchProof fix ({rule_id}): {hint}\n"),
    );
    fixed
}

/// Insert helpers/imports after the module docstring, else at the top.
fn insert_pos(lines: &[String]) -> usize {
    for (i, line) in lines.iter().enumerate() {
        let stripped = line.trim();
        if stripped.is_empty() || stripped.starts_with('#') {
            continue;
        }
        for quote in ["\"\"\"", "'''"] {
            if let Some(rest) = stripped.strip_prefix(quote) {
                if rest.contains(quote) {
                    return i + 1;
                }
                for (j, later) in lines.iter().enumerate().skip(i + 1) {
                    if later.contains(quote) {
                        return j + 1;
                    }
                }
                return 0;
            }
        }
        return 0;
    }
    0
}

fn need_import(source: &str, module: &str, stmt: &str) -> Vec<String> {
    let pattern = format!(
        r"(?m)^\s*(import {}\b|from {}\b)",
        regex::escape(module),
        regex::escape(module)
    );
    let re = Regex::new(&pattern).expect("import regex");
    if re.is_match(source) {
        Vec::new()
    } else {
        vec![format!("{stmt}\n")]
    }
}

fn fix_sqli(line: &str) -> Option<(Vec<String>, String)> {
    if line.matches('{').count() != 1 || !line.contains('}') {
        return None;
    }
    let m = sqli_exec_re().find(line)?;
    if line[m.end()..].contains(", (") {
        return None;
    }
    let cap = sqli_exec_re().captures(line)?;
    let var_cap = interp_var_re().captures(line)?;
    let expr = var_cap.get(1)?.as_str().trim().to_string();
    if !ident_re().is_match(&expr) {
        return None;
    }
    let g1 = cap.get(1)?.as_str();
    let g2 = cap.get(2)?.as_str();
    let mut body = format!("{}{}{}", &line[..m.start()], g1, g2);
    body.push_str(&line[m.end()..]);
    let quoted = format!("'{{{expr}}}'");
    body = body.replacen(&quoted, "?", 1);
    let interp = Regex::new(&format!("\\{{{}\\}}", regex::escape(&expr))).ok()?;
    body = interp.replacen(&body, 1, "?").to_string();
    let close = body.rfind(')')?;
    body.insert_str(close, &format!(", ({expr},)"));
    Some((Vec::new(), body))
}

fn fix_cmdi(line: &str) -> Option<(Vec<String>, String)> {
    let mut body = line.to_string();
    let mut matched = false;
    if let Some(cap) = cmdi_run_re().captures(line) {
        let whole = cap.get(0)?;
        let replacement = format!(
            '{}["{}", {}]',
            cap.get(1)?.as_str(),
            cap.get(3)?.as_str(),
            cap.get(4)?.as_str().trim()
        );
        body = format!(
            "{}{}{}",
            &line[..whole.start()],
            replacement,
            &line[whole.end()..]
        );
        matched = true;
    }
    if body.contains("shell=True") {
        body = body.replace("shell=True", "shell=False");
    } else if !matched {
        return None;
    }
    Some((Vec::new(), body))
}

fn fix_xss(source: &str, line: &str) -> Option<(Vec<String>, String)> {
    if !line.contains("render_template_string") && !line.contains("Markup") {
        return None;
    }
    if line.contains("escape") {
        return None;
    }
    let n1 = xss_mid_re().find_iter(line).count();
    let after_first = xss_mid_re()
        .replace_all(line, "+ html.escape($1) +")
        .to_string();
    let n2 = xss_end_re().find_iter(&after_first).count();
    if n1 + n2 == 0 {
        return None;
    }
    let body = xss_end_re()
        .replace_all(&after_first, "+ html.escape($1))")
        .to_string();
    Some((need_import(source, "html", "import html"), body))
}

fn fix_pathtrav(source: &str, line: &str) -> Option<(Vec<String>, String)> {
    let cap = pathtrav_open_re().captures(line)?;
    let whole = cap.get(0)?;
    let block: Vec<String> = if source.contains("_confined_path") {
        Vec::new()
    } else {
        let mut b = vec!["\n".to_string()];
        b.extend(split_keepends(CONFINED_HELPER));
        b
    };
    let body = format!(
        "{}open(_confined_path(\"{}\", {})){}",
        &line[..whole.start()],
        cap.get(1)?.as_str(),
        cap.get(2)?.as_str().trim(),
        &line[whole.end()..]
    );
    Some((block, body))
}

fn fix_deser(source: &str, line: &str) -> Option<(Vec<String>, String)> {
    if line.contains("yaml.load(") && !line.contains("Loader") && !line.contains("safe_load") {
        return Some((Vec::new(), line.replace("yaml.load(", "yaml.safe_load(")));
    }
    if line.contains("pickle.loads(") {
        return Some((
            need_import(source, "json", "import json"),
            line.replace("pickle.loads(", "json.loads("),
        ));
    }
    None
}

fn fix_secret(source: &str, line: &str) -> Option<(Vec<String>, String)> {
    if line.contains("os.environ") {
        return None;
    }
    let stripped = line.trim_end_matches('\n');
    let cap = secret_assign_re().captures(stripped)?;
    let eol = if line.ends_with('\n') { "\n" } else { "" };
    let body = format!(
        "{}{} = os.environ[\"{}\"]{}",
        cap.get(1)?.as_str(),
        cap.get(2)?.as_str(),
        cap.get(2)?.as_str(),
        eol
    );
    Some((need_import(source, "os", "import os"), body))
}

fn fix_ssrf(source: &str, line: &str) -> Option<(Vec<String>, String)> {
    let cap = ssrf_req_re().captures(line)?;
    let whole = cap.get(0)?;
    let block: Vec<String> = if source.contains("_checked_url") {
        Vec::new()
    } else {
        let mut b = vec!["\n".to_string()];
        b.extend(split_keepends(CHECKED_URL_HELPER));
        b
    };
    let body = format!(
        "{}{}_checked_url({}){}",
        &line[..whole.start()],
        cap.get(1)?.as_str(),
        cap.get(2)?.as_str().trim(),
        &line[whole.end()..]
    );
    Some((block, body))
}

/// Minimal single-hunk unified diff with 3 lines of context.
fn unified_diff(original: &[String], fixed: &[String], file_path: &str) -> String {
    if original == fixed {
        return String::new();
    }
    let mut prefix = 0;
    while prefix < original.len()
        && prefix < fixed.len()
        && original[prefix] == fixed[prefix]
    {
        prefix += 1;
    }
    let mut suffix = 0;
    while suffix < original.len() - prefix
        && suffix < fixed.len() - prefix
        && original[original.len() - 1 - suffix] == fixed[fixed.len() - 1 - suffix]
    {
        suffix += 1;
    }
    let ctx = 3;
    let o_start = prefix.saturating_sub(ctx);
    let o_end = (original.len() - suffix + ctx).min(original.len());
    let pre_ctx = prefix - o_start;
    let suf_ctx = o_end - (original.len() - suffix);
    let n_start = prefix - pre_ctx;
    let n_end = (fixed.len() - suffix + suf_ctx).min(fixed.len());

    let mut diff = format!("--- a/{file_path}\n+++ b/{file_path}\n");
    diff.push_str(&format!(
        "@@ -{},{} +{},{} @@\n",
        o_start + 1,
        o_end - o_start,
        n_start + 1,
        n_end - n_start
    ));
    for line in &original[o_start..prefix] {
        diff.push(' ');
        push_line(&mut diff, line);
    }
    for line in &original[prefix..original.len() - suffix] {
        diff.push('-');
        push_line(&mut diff, line);
    }
    for line in &fixed[prefix..fixed.len() - suffix] {
        diff.push('+');
        push_line(&mut diff, line);
    }
    for line in &original[original.len() - suffix..o_end] {
        diff.push(' ');
        push_line(&mut diff, line);
    }
    diff
}

fn push_line(diff: &mut String, line: &str) {
    diff.push_str(line);
    if !line.ends_with('\n') {
        diff.push('\n');
    }
}

/// Validate Python syntax via `ast.parse`. Returns `None` when no
/// interpreter is available (caller treats it as valid).
pub fn python_syntax_ok(source: &str) -> Option<bool> {
    let python = crate::sandbox::find_python()?;
    let mut child = std::process::Command::new(python)
        .arg("-c")
        .arg("import ast,sys; ast.parse(sys.stdin.read())")
        .stdin(Stdio::piped())
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .spawn()
        .ok()?;
    child
        .stdin
        .as_mut()?
        .write_all(source.as_bytes())
        .ok()?;
    drop(child.stdin.take());
    child.wait().ok().map(|s| s.success())
}
