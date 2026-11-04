//! Static detectors for the MVP vulnerability classes (ports
//! `backend/app/scanner/rules.py`).
//!
//! The Python implementation walks a CPython AST with a regex fallback. This
//! port uses line-oriented regular expressions that reproduce the same
//! observable findings: the same 7 rules fire on the same single-line sinks,
//! skip the same hardened shapes, and dedupe on `(rule_id, line_no)`.
//!
//! Known approximation: multi-line calls are attributed to the line carrying
//! the tell-tale token (e.g. `shell=True`) rather than the call's first line.
//! Full-line comments are skipped (the Python AST walker never sees them),
//! and trailing `#` comments are stripped before matching, so advisory
//! comments can never self-trigger a rule.

use std::collections::HashSet;
use std::sync::OnceLock;

use regex::Regex;

/// (rule_id) -> (title, cwe, severity)
pub fn rule_meta(rule_id: &str) -> Option<(&'static str, &'static str, &'static str)> {
    match rule_id {
        "PY-SQLI-001" => Some(("Possible SQL injection", "CWE-89", "high")),
        "PY-CMDI-001" => Some(("Possible command injection", "CWE-78", "high")),
        "PY-XSS-001" => Some((
            "Possible cross-site scripting / unsafe template render",
            "CWE-79",
            "medium",
        )),
        "PY-PATHTRAV-001" => Some(("Possible path traversal", "CWE-22", "medium")),
        "PY-DESER-001" => Some(("Insecure deserialization", "CWE-502", "high")),
        "PY-SECRET-001" => Some(("Hardcoded secret", "CWE-798", "medium")),
        "PY-SSRF-001" => Some((
            "Possible SSRF (unvalidated request URL)",
            "CWE-918",
            "medium",
        )),
        _ => None,
    }
}

/// Ordered rule metadata for iteration.
pub const RULE_META: &[(&str, &str, &str, &str)] = &[
    ("PY-SQLI-001", "Possible SQL injection", "CWE-89", "high"),
    (
        "PY-CMDI-001",
        "Possible command injection",
        "CWE-78",
        "high",
    ),
    (
        "PY-XSS-001",
        "Possible cross-site scripting / unsafe template render",
        "CWE-79",
        "medium",
    ),
    (
        "PY-PATHTRAV-001",
        "Possible path traversal",
        "CWE-22",
        "medium",
    ),
    (
        "PY-DESER-001",
        "Insecure deserialization",
        "CWE-502",
        "high",
    ),
    ("PY-SECRET-001", "Hardcoded secret", "CWE-798", "medium"),
    (
        "PY-SSRF-001",
        "Possible SSRF (unvalidated request URL)",
        "CWE-918",
        "medium",
    ),
];

#[derive(Debug, Clone, PartialEq, Eq)]
pub struct RawFinding {
    pub rule_id: String,
    pub title: String,
    pub cwe: String,
    pub severity: String,
    pub confidence: String,
    /// 1-based line number.
    pub line_no: usize,
    pub snippet: String,
    pub explanation: String,
}

macro_rules! static_re {
    ($name:ident, $pattern:expr) => {
        fn $name() -> &'static Regex {
            static CELL: OnceLock<Regex> = OnceLock::new();
            CELL.get_or_init(|| Regex::new($pattern).expect("invalid regex"))
        }
    };
}

static_re!(
    secret_re,
    r#"(?i)\b(api[_-]?key|secret|password|passwd|pwd|token|aws_access|aws_secret|private[_-]?key)\b\s*[:=]\s*['"][^'"]{4,}['"]"#
);
static_re!(
    fstring_sql_re,
    r#"(?i)\b(SELECT|INSERT|UPDATE|DELETE)\b.*\{"#
);
static_re!(
    format_sql_re,
    r#"(?i)\b(SELECT|INSERT|UPDATE|DELETE)\b.*(\.format\(|%)"#
);
static_re!(
    execute_call_re,
    r#"\bexecutemany\s*\(|\bexecutescript\s*\(|\bexecute\s*\("#
);
static_re!(system_popen_re, r#"\b(system|popen)\s*\("#);
static_re!(shell_true_re, r#"(?i)\bshell\s*=\s*True\b"#);
static_re!(
    subprocess_call_re,
    r#"\b(Popen|run|call|check_output|check_call|system|popen)\s*\("#
);
static_re!(eval_re, r#"\beval\s*\("#);
static_re!(exec_re, r#"\bexec\s*\("#);
static_re!(
    exec_family_re,
    r#"\b(os\.)?(execl|execle|execlp|execv|execve|execvp|spawnl|spawnlp|spawnv|spawnvp|posix_spawn)\s*\("#
);
static_re!(render_call_re, r#"\brender_template_string\s*\("#);
static_re!(markup_call_re, r#"\bMarkup\s*\("#);
static_re!(open_call_re, r#"\bopen\s*\("#);
static_re!(pickle_call_re, r#"\bpickle\s*\.\s*loads?\s*\("#);
static_re!(yaml_load_re, r#"\byaml\s*\.\s*load\s*\("#);
static_re!(
    requests_call_re,
    r#"\brequests\s*\.\s*(get|post|put|delete|head|request)\s*\("#
);
static_re!(
    requests_first_arg_call_re,
    r#"\brequests\s*\.\s*\w+\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\("#
);

const SANITIZER_HINTS: &[&str] = &[
    "check", "allow", "valid", "sanit", "escape", "clean", "safe",
];

/// Scan one Python source file, returning raw findings.
pub fn scan_source(source: &str) -> Vec<RawFinding> {
    let lines: Vec<&str> = source.split('\n').collect();
    // Drop the pseudo-line after a trailing newline so numbering matches
    // Python's `splitlines()`.
    let lines: Vec<&str> = if lines.last() == Some(&"") {
        lines[..lines.len() - 1].to_vec()
    } else {
        lines
    };
    let mut findings = Vec::new();
    for (idx, line) in lines.iter().enumerate() {
        let lineno = idx + 1;
        scan_line(line, lineno, &lines, &mut findings);
    }
    dedupe(findings)
}

fn scan_line(line: &str, lineno: usize, lines: &[&str], out: &mut Vec<RawFinding>) {
    if line.trim_start().starts_with('#') {
        return;
    }
    // Match against code only: a trailing `#` comment must never trigger a
    // rule (e.g. `x = 1  # shell=True`).
    let code = strip_line_comment(line);
    let code = code.as_str();
    // SQL injection: execute-family with tainted input.
    if execute_call_re().is_match(code) && is_tainted_call_arg(code) {
        out.push(mk(
            "PY-SQLI-001",
            lineno,
            lines,
            "SQL statement built from interpolated input; use parameterized queries.",
            "high",
        ));
    }
    // Command injection: os.system / os.popen / bare system / popen.
    if system_popen_re().is_match(code) {
        out.push(mk(
            "PY-CMDI-001",
            lineno,
            lines,
            "Shell command executed from Python; attacker input may inject commands.",
            "medium",
        ));
    }
    // Command injection: shell=True on a subprocess-shaped call. A bare
    // `shell=True` with no call on the line (config flag, comment text) is
    // not a sink.
    if shell_true_re().is_match(code)
        && (code.contains("subprocess") || subprocess_call_re().is_match(code))
    {
        out.push(mk(
            "PY-CMDI-001",
            lineno,
            lines,
            "subprocess called with shell=True; prefer argv list with shell=False.",
            "high",
        ));
    }
    // XSS: unescaped template rendering.
    if (render_call_re().is_match(code) || markup_call_re().is_match(code))
        && !code.contains("escape")
    {
        out.push(mk(
            "PY-XSS-001",
            lineno,
            lines,
            "Unescaped template/HTML rendering; user input may execute as script.",
            "medium",
        ));
    }
    // Path traversal: open() with tainted path.
    if open_call_re().is_match(code) && (is_tainted_call_arg(code) || is_path_join_arg(code)) {
        out.push(mk(
            "PY-PATHTRAV-001",
            lineno,
            lines,
            "File opened with an interpolated path; validate and constrain to a base directory.",
            "medium",
        ));
    }
    // Insecure deserialization: pickle / yaml.load.
    if pickle_call_re().is_match(code) {
        out.push(mk(
            "PY-DESER-001",
            lineno,
            lines,
            "pickle deserialization of untrusted data can execute arbitrary code.",
            "high",
        ));
    }
    if yaml_load_re().is_match(code) && !code.contains("Loader") {
        out.push(mk(
            "PY-DESER-001",
            lineno,
            lines,
            "yaml.load without a safe Loader can execute arbitrary objects.",
            "high",
        ));
    }
    // Dynamic code execution: eval/exec plus the os.exec/spawn family.
    if eval_re().is_match(code) || exec_re().is_match(code) {
        out.push(mk(
            "PY-CMDI-001",
            lineno,
            lines,
            "Dynamic code execution via eval/exec on possibly untrusted input.",
            "high",
        ));
    }
    if exec_family_re().is_match(code) {
        out.push(mk(
            "PY-CMDI-001",
            lineno,
            lines,
            "Process execution via os.exec/spawn; attacker input may inject commands.",
            "medium",
        ));
    }
    // SSRF: requests.* with tainted or variable URL. Fully constant URLs
    // carry no attacker input and are not flagged.
    if requests_call_re().is_match(code) {
        if is_sanitizer_first_arg(code) {
            // Hardened shape such as requests.get(_checked_url(url)).
        } else if is_tainted_call_arg(code) {
            out.push(mk(
                "PY-SSRF-001",
                lineno,
                lines,
                "HTTP request URL built from input; validate against an allowlist.",
                "medium",
            ));
        } else if !is_constant_first_arg(code) {
            out.push(mk(
                "PY-SSRF-001",
                lineno,
                lines,
                "HTTP request to a variable URL; confirm the host is allowlisted.",
                "low",
            ));
        }
    }
    // Regex detectors: secrets and SQL keyword + interpolation.
    if secret_re().is_match(code) {
        out.push(mk(
            "PY-SECRET-001",
            lineno,
            lines,
            "Credential-like value hardcoded in source; move to env/secret store.",
            "medium",
        ));
    }
    if fstring_sql_re().is_match(code) || format_sql_re().is_match(code) {
        out.push(mk(
            "PY-SQLI-001",
            lineno,
            lines,
            "SQL keyword combined with string interpolation.",
            "medium",
        ));
    }
}

/// Heuristic taint: f-string, `.format(`, or `%`/`+` formatting applied to a
/// non-constant expression inside the first call argument (ports
/// `_is_tainted_string` for single-line sinks). Pure-constant expressions
/// such as `"a" + "b"` or `100 % 3` are not tainted.
fn is_tainted_call_arg(line: &str) -> bool {
    if line.contains("f\"") || line.contains("f'") || line.contains("F\"") || line.contains("F'") {
        return true;
    }
    if line.contains(".format(") {
        return true;
    }
    let stripped = strip_string_literals(first_arg_region(line));
    let has_op = stripped.contains('%') || stripped.contains('+');
    has_op
        && stripped
            .chars()
            .any(|c| c.is_ascii_alphabetic() || c == '_')
}

/// Path-join shapes the generic taint check misses: `os.path.join(...)`
/// and `Path(...) / name` compositions inside the first argument.
fn is_path_join_arg(line: &str) -> bool {
    let stripped = strip_string_literals(first_arg_region(line));
    if stripped.contains("join(") {
        return true;
    }
    stripped.contains('/')
        && stripped
            .chars()
            .any(|c| c.is_ascii_alphabetic() || c == '_')
}

/// True when the first call argument is a plain string constant.
fn is_constant_first_arg(line: &str) -> bool {
    matches!(
        first_arg_region(line).trim_start().chars().next(),
        Some('"') | Some('\'')
    )
}

/// Remove string-literal contents (quote-aware, single line) so operator
/// checks only see code.
fn strip_string_literals(region: &str) -> String {
    let mut out = String::with_capacity(region.len());
    let chars: Vec<char> = region.chars().collect();
    let mut i = 0;
    while i < chars.len() {
        let c = chars[i];
        if c == '"' || c == '\'' {
            let triple = i + 2 < chars.len() && chars[i + 1] == c && chars[i + 2] == c;
            i += if triple { 3 } else { 1 };
            while i < chars.len() {
                if triple {
                    if i + 2 < chars.len()
                        && chars[i] == c
                        && chars[i + 1] == c
                        && chars[i + 2] == c
                    {
                        i += 3;
                        break;
                    }
                    i += 1;
                } else if chars[i] == '\\' {
                    i += 2;
                } else if chars[i] == c {
                    i += 1;
                    break;
                } else {
                    i += 1;
                }
            }
        } else {
            out.push(c);
            i += 1;
        }
    }
    out
}

/// Cut a trailing `#` comment, ignoring `#` inside string literals.
fn strip_line_comment(line: &str) -> String {
    let bytes = line.as_bytes();
    let mut quote: Option<u8> = None;
    let mut i = 0;
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
        } else if b == b'#' {
            return line[..i].to_string();
        }
        i += 1;
    }
    line.to_string()
}

/// Text between the first `(` and the first top-level `,` or closing `)`.
fn first_arg_region(line: &str) -> &str {
    let bytes = line.as_bytes();
    let Some(open) = bytes.iter().position(|b| *b == b'(') else {
        return "";
    };
    let mut depth = 0i32;
    let mut end = line.len();
    for (i, b) in bytes.iter().enumerate().skip(open) {
        match b {
            b'(' => depth += 1,
            b')' => {
                depth -= 1;
                if depth == 0 {
                    end = i;
                    break;
                }
            }
            b',' if depth == 1 => {
                end = i;
                break;
            }
            _ => {}
        }
    }
    let start = (open + 1).min(line.len());
    &line[start..end.min(line.len())]
}

/// True when the first argument is a call to a validator-shaped helper.
fn is_sanitizer_first_arg(line: &str) -> bool {
    if let Some(cap) = requests_first_arg_call_re().captures(line) {
        if let Some(name) = cap.get(1) {
            let lower = name.as_str().to_ascii_lowercase();
            return SANITIZER_HINTS.iter().any(|h| lower.contains(h));
        }
    }
    false
}

fn mk(
    rule_id: &str,
    lineno: usize,
    lines: &[&str],
    explanation: &str,
    confidence: &str,
) -> RawFinding {
    let (title, cwe, severity) = rule_meta(rule_id).expect("known rule");
    RawFinding {
        rule_id: rule_id.to_string(),
        title: title.to_string(),
        cwe: cwe.to_string(),
        severity: severity.to_string(),
        confidence: confidence.to_string(),
        line_no: lineno,
        snippet: snippet(lines, lineno),
        explanation: explanation.to_string(),
    }
}

fn snippet(lines: &[&str], lineno: usize) -> String {
    let start = lineno.saturating_sub(2);
    let end = (lineno + 1).min(lines.len());
    (start..end)
        .map(|i| format!("{}: {}", i + 1, lines[i]))
        .collect::<Vec<_>>()
        .join("\n")
}

fn dedupe(findings: Vec<RawFinding>) -> Vec<RawFinding> {
    let mut seen: HashSet<(String, usize)> = HashSet::new();
    let mut out = Vec::new();
    for f in findings {
        if seen.insert((f.rule_id.clone(), f.line_no)) {
            out.push(f);
        }
    }
    out
}
