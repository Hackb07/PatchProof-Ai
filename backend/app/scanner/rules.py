"""Static detectors for the MVP vulnerability classes.

Each rule returns RawFinding dicts: rule_id, title, cwe, severity,
confidence, line_no, snippet, explanation.
"""
import ast
import re

RULE_META = {
    "PY-SQLI-001": ("Possible SQL injection", "CWE-89", "high"),
    "PY-CMDI-001": ("Possible command injection", "CWE-78", "high"),
    "PY-XSS-001": ("Possible cross-site scripting / unsafe template render", "CWE-79", "medium"),
    "PY-PATHTRAV-001": ("Possible path traversal", "CWE-22", "medium"),
    "PY-DESER-001": ("Insecure deserialization", "CWE-502", "high"),
    "PY-SECRET-001": ("Hardcoded secret", "CWE-798", "medium"),
    "PY-SSRF-001": ("Possible SSRF (unvalidated request URL)", "CWE-918", "medium"),
}

_SECRET_RE = re.compile(
    r"""(?i)\b(api[_-]?key|secret|password|passwd|pwd|token|aws_access|aws_secret|private[_-]?key)\b\s*[:=]\s*['\"][^'"]{4,}['\"]"""
)
_FSTRING_SQL_RE = re.compile(r"""(?i)\b(SELECT|INSERT|UPDATE|DELETE)\b.*\{""")
_FORMAT_SQL_RE = re.compile(r"""(?i)\b(SELECT|INSERT|UPDATE|DELETE)\b.*(\.format\(|%\s)""")


def _lines(source: str) -> list[str]:
    return source.splitlines()


def _snippet(lines: list[str], lineno: int) -> str:
    start = max(0, lineno - 2)
    return "\n".join(f"{i + 1}: {lines[i]}" for i in range(start, min(len(lines), lineno + 1)))


def _mk(rule_id: str, lineno: int, lines: list[str], explanation: str, confidence: str = "medium") -> dict:
    title, cwe, severity = RULE_META[rule_id]
    return {
        "rule_id": rule_id,
        "title": title,
        "cwe": cwe,
        "severity": severity,
        "confidence": confidence,
        "line_no": lineno,
        "snippet": _snippet(lines, lineno),
        "explanation": explanation,
    }


def _is_tainted_string(node: ast.AST) -> bool:
    """Heuristic: f-string, .format(), %-format, or BinOp + with a Name inside."""
    if isinstance(node, ast.JoinedStr):
        return True
    if isinstance(node, ast.Call) and isinstance(node.func, ast.Attribute) and node.func.attr == "format":
        return True
    if isinstance(node, ast.BinOp) and isinstance(node.op, (ast.Mod, ast.Add)):
        return True
    return False


def _call_name(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Name):
        return func.id
    if isinstance(func, ast.Attribute):
        return func.attr
    return ""


_SANITIZER_HINTS = ("check", "allow", "valid", "sanit", "escape", "clean", "safe")


def _is_sanitizer_call(node: ast.AST) -> bool:
    """True when the URL flows through a validator-shaped helper (patched code)."""
    if not isinstance(node, ast.Call):
        return False
    return any(h in _call_name(node).lower() for h in _SANITIZER_HINTS)


def _call_module(node: ast.Call) -> str:
    func = node.func
    if isinstance(func, ast.Attribute) and isinstance(func.value, ast.Name):
        return func.value.id
    return ""


def scan_source(source: str, filename: str = "<memory>") -> list[dict]:
    del filename  # detectors are filename-agnostic in the MVP
    lines = _lines(source)
    findings: list[dict] = []
    try:
        tree = ast.parse(source)
    except SyntaxError:
        return _regex_fallback(source, lines)

    for node in ast.walk(tree):
        if isinstance(node, ast.Call):
            name = _call_name(node)
            mod = _call_module(node)
            lineno = getattr(node, "lineno", 1)

            # SQL injection: execute/query with tainted string
            if name in {"execute", "executemany", "executescript"} and node.args and _is_tainted_string(node.args[0]):
                findings.append(_mk("PY-SQLI-001", lineno, lines,
                                    "SQL statement built from interpolated input; use parameterized queries.", "high"))
            # Command injection: os.system / subprocess with shell=True / os.popen
            if (mod == "os" and name in {"system", "popen"}) or name in {"system", "popen"}:
                findings.append(_mk("PY-CMDI-001", lineno, lines,
                                    "Shell command executed from Python; attacker input may inject commands.", "medium"))
            if mod == "subprocess" or name in {"Popen", "call", "run", "check_output", "check_call"}:
                shell_true = any(kw.arg == "shell" and isinstance(kw.value, ast.Constant) and kw.value.value is True
                                 for kw in node.keywords)
                if shell_true:
                    findings.append(_mk("PY-CMDI-001", lineno, lines,
                                        "subprocess called with shell=True; prefer argv list with shell=False.", "high"))
            # XSS: Flask render_template_string / markupsafe.Markup with tainted input
            if name in {"render_template_string", "Markup"}:
                # Patched code escapes interpolated values; don't re-flag it.
                if 1 <= lineno <= len(lines) and "escape" in lines[lineno - 1]:
                    pass
                else:
                    findings.append(_mk("PY-XSS-001", lineno, lines,
                                        "Unescaped template/HTML rendering; user input may execute as script.", "medium"))
            # Path traversal: open() with tainted path
            if name in {"open"} and node.args and _is_tainted_string(node.args[0]):
                findings.append(_mk("PY-PATHTRAV-001", lineno, lines,
                                    "File opened with an interpolated path; validate and constrain to a base directory.", "medium"))
            # Insecure deserialization: pickle/yaml loads
            if (mod == "pickle" and name in {"loads", "load"}) or (mod == "yaml" and name == "load"):
                if mod == "yaml":
                    safe = any(kw.arg == "Loader" for kw in node.keywords)
                    if not safe:
                        findings.append(_mk("PY-DESER-001", lineno, lines,
                                            "yaml.load without a safe Loader can execute arbitrary objects.", "high"))
                else:
                    findings.append(_mk("PY-DESER-001", lineno, lines,
                                        "pickle deserialization of untrusted data can execute arbitrary code.", "high"))
            if name == "eval" or (name == "exec" and mod == ""):
                # eval/exec reported under deserialization-adjacent code execution; keep as CMDI-adjacent high
                findings.append(_mk("PY-CMDI-001", lineno, lines,
                                    "Dynamic code execution via eval/exec on possibly untrusted input.", "high"))
            # SSRF: requests.* with tainted URL
            if mod == "requests" and name in {"get", "post", "put", "delete", "head", "request"}:
                if node.args and _is_tainted_string(node.args[0]):
                    findings.append(_mk("PY-SSRF-001", lineno, lines,
                                        "HTTP request URL built from input; validate against an allowlist.", "medium"))
                elif node.args and not _is_sanitizer_call(node.args[0]):
                    findings.append(_mk("PY-SSRF-001", lineno, lines,
                                        "HTTP request to a variable URL; confirm the host is allowlisted.", "low"))

    findings.extend(_regex_detectors(source, lines))
    return _dedupe(findings)


def _regex_detectors(source: str, lines: list[str]) -> list[dict]:
    out: list[dict] = []
    for i, line in enumerate(lines, start=1):
        if _SECRET_RE.search(line):
            out.append(_mk("PY-SECRET-001", i, lines, "Credential-like value hardcoded in source; move to env/secret store."))
        if _FSTRING_SQL_RE.search(line) or _FORMAT_SQL_RE.search(line):
            out.append(_mk("PY-SQLI-001", i, lines, "SQL keyword combined with string interpolation.", "medium"))
    # eval/exec fallback for odd parse shapes is covered by AST; keep secrets+SQL here.
    del source
    return out


def _regex_fallback(source: str, lines: list[str]) -> list[dict]:
    out = _regex_detectors(source, lines)
    for i, line in enumerate(lines, start=1):
        low = line.lower()
        if "shell=true" in low:
            out.append(_mk("PY-CMDI-001", i, lines, "subprocess with shell=True (regex fallback)."))
        if "pickle.loads" in low or "pickle.load" in low:
            out.append(_mk("PY-DESER-001", i, lines, "pickle deserialization (regex fallback)."))
    return _dedupe(out)


def _dedupe(findings: list[dict]) -> list[dict]:
    seen: set[tuple[str, int]] = set()
    out: list[dict] = []
    for f in findings:
        key = (f["rule_id"], f["line_no"])
        if key not in seen:
            seen.add(key)
            out.append(f)
    return out
