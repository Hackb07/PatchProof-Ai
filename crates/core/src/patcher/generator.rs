//! Minimal patch generation: deterministic per-rule transforms (ports
//! `backend/app/patcher/generator.py`).
//!
//! The deterministic transforms below guarantee a safe, reviewable diff
//! even offline. Every transform is gated on a Python `ast.parse` check
//! when an interpreter is available, with a bracket-balance plausibility
//! check as the offline stand-in — otherwise the patcher falls back to an
//! advisory comment.

use std::io::Write;
use std::path::Path;
use std::process::Stdio;
use std::sync::OnceLock;

use regex::Regex;

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
    root = _PPPath(base).resolve()
    p = (root / name).resolve()
    try:
        p.relative_to(root)
    except ValueError:
        raise ValueError("path escapes base directory")
    return str(p)


"#;

pub const CHECKED_URL_HELPER: &str = r#"import ipaddress as _pp_ip
from urllib.parse import urlparse as _pp_urlparse


def _checked_url(url):
    """Reject non-allowlisted/internal hosts (PatchProof fix).

    Denylist guard: sensitive callers should use a strict allowlist of
    expected hosts instead.
    """
    host = (_pp_urlparse(url).hostname or "").lower().rstrip(".")
    if not host or host.isdigit():
        raise ValueError("URL host is not allowlisted")
    if host == "localhost" or host.endswith((".localhost", ".internal", ".local", ".lan")):
        raise ValueError("URL host is not allowlisted")
    try:
        ip = _pp_ip.ip_address(host)
    except ValueError:
        pass
    else:
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
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
static_re!(sqli_exec_re, r#"(\.execute(?:many|script)?\(\s*)f(["'])"#);
static_re!(
    cmdi_run_re,
    r#"(subprocess\.\w+\(\s*)f(["'])(.*?)\{([^{}]+)\}(.*?)["']"#
);
static_re!(subprocess_list_arg_re, r#"subprocess\.\w+\(\s*\["#);
static_re!(interp_var_re, r#"\{([^{}]+)\}"#);
static_re!(ident_re, r#"^[A-Za-z_][A-Za-z0-9_]*$"#);
static_re!(xss_mid_re, r#"\+\s*([A-Za-z_][A-Za-z0-9_]*)\s*\+"#);
static_re!(xss_end_re, r#"\+\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)"#);
static_re!(
    pathtrav_open_re,
    r#"open\(\s*f"([^"{}\n]*)/\{([^{}]+)\}"\s*\)"#
);
static_re!(
    ssrf_req_re,
    r#"(requests\.(?:get|post|put|delete|head|request)\(\s*)f"\{([^{}]+)\}""#
);

/// Generate one patch per non-false-positive finding.
pub async fn generate_patches(store: &Store, scan_id: &str, repo_path: &str) -> Result<Vec<Patch>> {
    let findings = store.list_active_findings(scan_id)?;
    let mut patches = Vec::new();
    for f in &findings {
        let hint = fix_hint(&f.rule_id);
        let (diff, summary) =
            deterministic_fix(repo_path, &f.file_path, f.line_no, &f.rule_id, hint);
        let patch = store.create_patch(&f.id, &diff, &summary)?;
        store.add_evidence(
            scan_id,
            "patch",
            "patcher",
            &format!(
                "Patch {} for {} at {}:{}",
                patch.id, f.rule_id, f.file_path, f.line_no
            ),
            &patch.id,
        )?;
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
        Err(_) => {
            return (
                String::new(),
                "Target file unreadable; manual fix required.".to_string(),
            )
        }
    };
    let content = String::from_utf8_lossy(&bytes).to_string();
    let original = split_keepends(&content);
    if original.is_empty() {
        return (
            String::new(),
            "Target file empty; manual fix required.".to_string(),
        );
    }
    match apply_real_fix(&original, line_no, rule_id) {
        Some((fixed, top_pos, top_len, sink_idx)) => {
            let summary = format!("Minimal fix for {rule_id} at line {line_no}: {hint}");
            let diff = structured_diff(&original, &fixed, top_pos, top_len, sink_idx, file_path);
            (diff, summary)
        }
        None => {
            let summary = format!("Advisory patch for {rule_id} at line {line_no}: {hint}");
            let (fixed, top_pos, top_len, sink_idx) = advisory_fix(&original, line_no, rule_id);
            let diff = structured_diff(&original, &fixed, top_pos, top_len, sink_idx, file_path);
            (diff, summary)
        }
    }
}

fn split_keepends(s: &str) -> Vec<String> {
    if s.is_empty() {
        return Vec::new();
    }
    s.split_inclusive('\n').map(|l| l.to_string()).collect()
}

/// A real fix plus its layout: `(fixed, top_pos, top_len, sink_idx0)`,
/// where `fixed = original[..top_pos] + top_block + original[top_pos..]`
/// with the sink line replaced.
fn apply_real_fix(
    original: &[String],
    line_no: i64,
    rule_id: &str,
) -> Option<(Vec<String>, usize, usize, usize)> {
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
    new.insert(
        idx,
        format!("{indent}# PatchProof fix ({rule_id}): {hint}\n"),
    );
    let top_len = top_block.len();
    match python_syntax_ok(&new.concat()) {
        Some(valid) => valid.then_some((new, top_pos, top_len, idx0)),
        // No interpreter: accept the fix only if bracket structure is
        // intact (best-effort stand-in for the ast.parse gate).
        None => brackets_balanced(&new.concat()).then_some((new, top_pos, top_len, idx0)),
    }
}

fn advisory_fix(
    original: &[String],
    line_no: i64,
    rule_id: &str,
) -> (Vec<String>, usize, usize, usize) {
    let idx = (line_no - 1).max(0).min(original.len() as i64 - 1) as usize;
    let line = &original[idx];
    let indent: String = line.chars().take_while(|c| c.is_whitespace()).collect();
    let hint = fix_hint(rule_id);
    let mut fixed = original.to_vec();
    fixed.insert(
        idx,
        format!("{indent}# PatchProof fix ({rule_id}): {hint}\n"),
    );
    (fixed, 0, 0, idx)
}

/// Insert helpers/imports after the shebang, encoding cookie, module
/// docstring, and `from __future__` imports (which must stay first).
fn insert_pos(lines: &[String]) -> usize {
    let mut idx = 0;
    if lines.first().is_some_and(|l| l.starts_with("#!")) {
        idx = 1;
    }
    for (i, line) in lines.iter().enumerate().skip(idx).take(2) {
        if line.contains("coding:") || line.contains("coding=") {
            idx = i + 1;
            break;
        }
    }
    let mut i = idx;
    while i < lines.len() {
        let stripped = lines[i].trim();
        if stripped.is_empty() || stripped.starts_with('#') {
            i += 1;
            continue;
        }
        break;
    }
    for quote in ["\"\"\"", "'''"] {
        if lines
            .get(i)
            .is_some_and(|l| l.trim_start().starts_with(quote))
        {
            let rest = lines[i].trim_start()[quote.len()..].to_string();
            if rest.contains(quote) {
                idx = i + 1;
            } else {
                for (j, later) in lines.iter().enumerate().skip(i + 1) {
                    if later.contains(quote) {
                        idx = j + 1;
                        break;
                    }
                }
            }
            i = idx;
            break;
        }
    }
    let mut j = i;
    while j < lines.len() {
        let stripped = lines[j].trim();
        if stripped.is_empty() {
            j += 1;
            continue;
        }
        if stripped.starts_with("from __future__ import ") {
            idx = j + 1;
            j += 1;
            continue;
        }
        break;
    }
    idx.min(lines.len())
}

fn need_import(source: &str, module: &str, stmt: &str) -> Vec<String> {
    // Only `import <module>` (without `as`) binds the plain module name;
    // `from <module> import ...` and `import <module> as ...` do not.
    for line in source.lines() {
        if let Some(rest) = line.trim_start().strip_prefix("import ") {
            let list = rest.split('#').next().unwrap_or("");
            for part in list.split(',') {
                let part = part.trim();
                if part == module || part.starts_with(&format!("{module}.")) {
                    return Vec::new();
                }
            }
        }
    }
    vec![format!("{stmt}\n")]
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
    // Drop quotes around the placeholder: `'{x}'` or `"{x}"` becomes `?`.
    let single = format!("'{{{expr}}}'");
    let double = format!("\"{{{expr}}}\"");
    if body.contains(&single) {
        body = body.replacen(&single, "?", 1);
    } else if body.contains(&double) {
        body = body.replacen(&double, "?", 1);
    } else {
        body = body.replacen(&format!("{{{expr}}}"), "?", 1);
    }
    // Append the parameter tuple at the end of the execute(...) call,
    // located by paren matching so trailing-comment parens can't mislead it.
    let exec_pos = body.find("execute")?;
    let mut open = exec_pos + "execute".len();
    while body
        .as_bytes()
        .get(open)
        .is_some_and(|b| b.is_ascii_alphanumeric() || *b == b'_')
    {
        open += 1;
    }
    while body
        .as_bytes()
        .get(open)
        .is_some_and(|b| b.is_ascii_whitespace())
    {
        open += 1;
    }
    if body.as_bytes().get(open) != Some(&b'(') {
        return None;
    }
    let close = find_matching_paren(&body, open)?;
    body.insert_str(close, &format!(", ({expr},)"));
    Some((Vec::new(), body))
}

/// Byte index of the `)` matching the `(` at `open` (quote-aware, and
/// bails out at a `#` comment since no code paren can follow it).
fn find_matching_paren(s: &str, open: usize) -> Option<usize> {
    let bytes = s.as_bytes();
    if bytes.get(open) != Some(&b'(') {
        return None;
    }
    let mut depth = 0i32;
    let mut quote: Option<u8> = None;
    let mut i = open;
    while i < bytes.len() {
        let b = bytes[i];
        if let Some(q) = quote {
            if b == b'\\' {
                i += 2;
                continue;
            }
            if b == q {
                quote = None;
            }
        } else if b == b'"' || b == b'\'' {
            quote = Some(b);
        } else if b == b'(' {
            depth += 1;
        } else if b == b')' {
            depth -= 1;
            if depth == 0 {
                return Some(i);
            }
        } else if b == b'#' {
            return None;
        }
        i += 1;
    }
    None
}

fn fix_cmdi(line: &str) -> Option<(Vec<String>, String)> {
    if let Some(cap) = cmdi_run_re().captures(line) {
        let before = cap.get(3)?.as_str();
        let var = cap.get(4)?.as_str().trim();
        let after = cap.get(5)?.as_str();
        // Exactly one interpolation; anything else gets an advisory comment.
        if !before.contains(['{', '}'])
            && !after.contains(['{', '}'])
            && !before.contains(['"', '\'', '\\'])
            && !after.contains(['"', '\'', '\\'])
            && ident_re().is_match(var)
        {
            let mut argv: Vec<String> = before
                .split_whitespace()
                .map(|t| format!("\"{t}\""))
                .collect();
            argv.push(var.to_string());
            argv.extend(after.split_whitespace().map(|t| format!("\"{t}\"")));
            if !argv.is_empty() {
                let whole = cap.get(0)?;
                let mut body = format!(
                    "{}{}[{}]",
                    &line[..whole.start()],
                    cap.get(1)?.as_str(),
                    argv.join(", ")
                );
                body.push_str(&line[whole.end()..]);
                body = body.replace("shell=True", "shell=False");
                return Some((Vec::new(), body));
            }
        }
    }
    // A bare shell flip is only safe when the command is already an argv
    // list; flipping a plain string would break the call at runtime.
    if line.contains("shell=True") && subprocess_list_arg_re().is_match(line) {
        return Some((Vec::new(), line.replace("shell=True", "shell=False")));
    }
    None
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
    if line.contains("pickle.load(") {
        return Some((
            need_import(source, "json", "import json"),
            line.replace("pickle.load(", "json.load("),
        ));
    }
    None
}

/// Best-effort syntax plausibility used when no Python interpreter is
/// available: brackets must balance outside strings and comments.
fn brackets_balanced(text: &str) -> bool {
    let mut stack: Vec<char> = Vec::new();
    let mut quote: Option<char> = None;
    let mut triple = false;
    let mut chars = text.chars().peekable();
    while let Some(c) = chars.next() {
        if let Some(q) = quote {
            if c == '\\' {
                chars.next();
                continue;
            }
            if triple {
                if c == q && chars.clone().take(2).all(|x| x == q) {
                    chars.next();
                    chars.next();
                    quote = None;
                    triple = false;
                }
            } else if c == q || c == '\n' {
                // Closing quote, or a newline ending an unterminated
                // single-line string (don't poison the rest of the file).
                quote = None;
            }
            continue;
        }
        match c {
            '"' | '\'' => {
                let mut ahead = chars.clone();
                triple = ahead.next() == Some(c) && ahead.next() == Some(c);
                if triple {
                    chars.next();
                    chars.next();
                }
                quote = Some(c);
            }
            '#' => {
                for next in chars.by_ref() {
                    if next == '\n' {
                        break;
                    }
                }
            }
            '(' | '[' | '{' => stack.push(c),
            ')' | ']' | '}' => {
                let open = stack.pop();
                if !matches!(
                    (open, c),
                    (Some('('), ')') | (Some('['), ']') | (Some('{'), '}')
                ) {
                    return false;
                }
            }
            _ => {}
        }
    }
    stack.is_empty() && quote.is_none()
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

const DIFF_CTX: usize = 3;

/// Structured unified diff: one hunk for the top-of-file helper/import
/// insertion (if any) plus one hunk for the sink change. Small local hunks
/// keep sequential application working — a single hunk spanning the whole
/// file would embed other (already patched) sinks in its context and fail
/// to match.
fn structured_diff(
    original: &[String],
    fixed: &[String],
    top_pos: usize,
    top_len: usize,
    sink_idx: usize,
    file_path: &str,
) -> String {
    if original == fixed {
        return String::new();
    }
    // fixed = original[..top_pos] + top_block + original[top_pos..sink_idx]
    //         + sink_new + original[sink_idx+1..]; slice the new parts out.
    let fixed_sink_start = sink_idx + top_len;
    let fixed_sink_end = fixed.len() - (original.len() - (sink_idx + 1));
    if top_pos > original.len() || fixed_sink_end < fixed_sink_start || fixed_sink_end > fixed.len()
    {
        return spanning_diff(original, fixed, file_path);
    }
    let top_block = &fixed[top_pos..top_pos + top_len];
    let sink_new = &fixed[fixed_sink_start..fixed_sink_end];

    // Top hunk uses below-only context so stacked top insertions from
    // earlier patches (which sit between the anchor and the imports) still
    // match by content.
    let top_ctx_end = (top_pos + DIFF_CTX).min(original.len());
    let sink_start = sink_idx.saturating_sub(DIFF_CTX);
    let sink_end = (sink_idx + 1 + DIFF_CTX).min(original.len());
    if top_len > 0 && sink_start < top_ctx_end {
        // Regions overlap (sink near the top of the file): one hunk.
        return spanning_diff(original, fixed, file_path);
    }

    let mut diff = format!("--- a/{file_path}\n+++ b/{file_path}\n");
    let mut added_before: usize = 0;
    if top_len > 0 {
        let old = &original[top_pos..top_ctx_end];
        let mut new_lines: Vec<&String> = Vec::with_capacity(top_block.len() + old.len());
        new_lines.extend(top_block.iter());
        new_lines.extend(old.iter());
        render_hunk(
            &mut diff,
            top_pos,
            old,
            &new_lines.into_iter().cloned().collect::<Vec<_>>(),
            added_before,
            HunkOrder::AddedFirst,
        );
        added_before += top_block.len();
    }
    let old = &original[sink_start..sink_end];
    let mut new_lines: Vec<String> =
        Vec::with_capacity(old.len() + sink_new.len().saturating_sub(1));
    new_lines.extend_from_slice(&original[sink_start..sink_idx]);
    new_lines.extend_from_slice(sink_new);
    new_lines.extend_from_slice(&original[sink_idx + 1..sink_end]);
    let pre_len = sink_idx - sink_start;
    render_hunk(
        &mut diff,
        sink_start,
        old,
        &new_lines,
        added_before,
        HunkOrder::ReplaceMiddle {
            pre_len,
            old_mid_len: 1,
        },
    );
    diff
}

enum HunkOrder {
    /// New lines come before the (context-only) old lines.
    AddedFirst,
    /// Old lines are `[pre_ctx, old_mid, post_ctx]`; new lines are
    /// `[pre_ctx, new_mid..., post_ctx]`.
    ReplaceMiddle { pre_len: usize, old_mid_len: usize },
}

fn render_hunk(
    diff: &mut String,
    old_start0: usize,
    old: &[String],
    new: &[String],
    added_before: usize,
    order: HunkOrder,
) {
    let new_start0 = old_start0 + added_before;
    diff.push_str(&format!(
        "@@ -{},{} +{},{} @@\n",
        old_start0 + 1,
        old.len(),
        new_start0 + 1,
        new.len()
    ));
    match order {
        HunkOrder::AddedFirst => {
            for line in &new[..new.len() - old.len()] {
                diff.push('+');
                push_line(diff, line);
            }
            for line in old {
                diff.push(' ');
                push_line(diff, line);
            }
        }
        HunkOrder::ReplaceMiddle {
            pre_len,
            old_mid_len,
        } => {
            let new_mid_len = new.len() + old_mid_len - old.len();
            for line in &old[..pre_len] {
                diff.push(' ');
                push_line(diff, line);
            }
            for line in &old[pre_len..pre_len + old_mid_len] {
                diff.push('-');
                push_line(diff, line);
            }
            for line in &new[pre_len..pre_len + new_mid_len] {
                diff.push('+');
                push_line(diff, line);
            }
            for line in &old[pre_len + old_mid_len..] {
                diff.push(' ');
                push_line(diff, line);
            }
        }
    }
}

/// Single-hunk fallback spanning the whole change with 3 lines of context.
fn spanning_diff(original: &[String], fixed: &[String], file_path: &str) -> String {
    if original == fixed {
        return String::new();
    }
    let mut prefix = 0;
    while prefix < original.len() && prefix < fixed.len() && original[prefix] == fixed[prefix] {
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
    child.stdin.as_mut()?.write_all(source.as_bytes()).ok()?;
    drop(child.stdin.take());
    child.wait().ok().map(|s| s.success())
}
