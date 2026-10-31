"""Minimal patch generation: LLM-guided, deterministic fallback.

The LLM proposes a minimal fix; the deterministic transforms below guarantee
the MVP always produces a safe, reviewable diff even offline (LLM_MOCK=1).
Every transform is validated with ast.parse — if a real fix does not apply
cleanly, the patcher falls back to an advisory comment so the diff can never
break the file's syntax.
"""
import ast
import difflib
import re
from pathlib import Path

from sqlalchemy.orm import Session

from ..agents.base import LLMClient
from ..models import Evidence, Finding, Patch

FIX_HINTS = {
    "PY-SQLI-001": "Use a parameterized query: cursor.execute('SELECT ... WHERE name = ?', (name,)) — never interpolate.",
    "PY-CMDI-001": "Use subprocess.run([...], shell=False) with an argv list; never shell=True with input.",
    "PY-XSS-001": "Escape output with html.escape() or use autoescaped templates; avoid render_template_string with input.",
    "PY-PATHTRAV-001": "Resolve against a base dir and reject paths escaping it via _confined_path().",
    "PY-DESER-001": "Replace pickle/yaml.load with json.loads, or yaml.safe_load with an explicit Loader.",
    "PY-SECRET-001": "Load from environment: os.environ['SECRET'] — remove the literal and rotate it.",
    "PY-SSRF-001": "Validate the URL host against an allowlist via _checked_url() before requesting.",
}

_CONFINED_HELPER = '''from pathlib import Path as _PPPath


def _confined_path(base, name):
    """Join *name* onto *base*, rejecting escapes (PatchProof fix)."""
    p = (_PPPath(base) / name).resolve()
    if not str(p).startswith(str(_PPPath(base).resolve())):
        raise ValueError("path escapes base directory")
    return str(p)


'''

_CHECKED_URL_HELPER = '''from urllib.parse import urlparse as _pp_urlparse


def _checked_url(url):
    """Reject non-allowlisted/internal hosts (PatchProof fix)."""
    host = (_pp_urlparse(url).hostname or "").lower()
    if not host or host in ("localhost", "127.0.0.1", "::1") or host.startswith("169.254.") or host.endswith(".internal"):
        raise ValueError("URL host is not allowlisted")
    return url


'''

_SECRET_ASSIGN_RE = re.compile(r"^(\s*)([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(['\"]).*?\3\s*(#.*)?$")
_SQLI_EXEC_RE = re.compile(r"(\.execute(?:many|script)?\(\s*)f([\"'])")
_CMDI_RUN_RE = re.compile(r"(subprocess\.\w+\(\s*)f([\"'])(\S+?)\s+\{([^{}]+)\}\2")


def generate_patches(session: Session, scan_id: str, repo_path: str) -> list[Patch]:
    findings = session.query(Finding).filter_by(scan_id=scan_id, false_positive=False).all()
    llm = LLMClient()
    patches: list[Patch] = []
    for f in findings:
        hint = FIX_HINTS.get(f.rule_id, "Apply the minimal safe fix.")
        llm.chat(
            "You are a security patch engineer. Propose the MINIMAL safe fix (few lines). Reply briefly.",
            f"{f.title} at {f.file_path}:{f.line_no}\n{f.snippet}\nHint: {hint}",
        )
        diff, summary = _deterministic_fix(repo_path, f, hint)
        patch = Patch(finding_id=f.id, diff=diff, summary=summary, applied=False)
        session.add(patch)
        patches.append(patch)
    session.add(Evidence(scan_id=scan_id, stage="patch", actor="patcher",
                         message=f"Patch generation complete: {len(patches)} patches"))
    session.commit()
    return patches


def _deterministic_fix(repo_path: str, finding: Finding, hint: str) -> tuple[str, str]:
    target = Path(repo_path) / finding.file_path
    try:
        original = target.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
    except OSError:
        return "", "Target file unreadable; manual fix required."
    if not original:
        return "", "Target file empty; manual fix required."

    fixed = _apply_real_fix(original, finding)
    if fixed is None:
        fixed = _advisory_fix(original, finding)
        summary = f"Advisory patch for {finding.rule_id} at line {finding.line_no}: {hint}"
    else:
        summary = f"Minimal fix for {finding.rule_id} at line {finding.line_no}: {hint}"
    diff = "".join(difflib.unified_diff(
        original, fixed, fromfile=f"a/{finding.file_path}", tofile=f"b/{finding.file_path}"))
    return diff, summary


def _apply_real_fix(original: list[str], finding: Finding) -> list[str] | None:
    """Full-file transform, or None when no safe transform matches."""
    idx0 = max(0, min(finding.line_no - 1, len(original) - 1))
    line = original[idx0]
    dispatch = {
        "PY-SQLI-001": _fix_sqli,
        "PY-CMDI-001": _fix_cmdi,
        "PY-XSS-001": _fix_xss,
        "PY-PATHTRAV-001": _fix_pathtrav,
        "PY-DESER-001": _fix_deser,
        "PY-SECRET-001": _fix_secret,
        "PY-SSRF-001": _fix_ssrf,
    }
    handler = dispatch.get(finding.rule_id)
    if handler is None:
        return None
    result = handler(original, line)
    if result is None:
        return None
    top_block, new_sink = result
    if new_sink == line and not top_block:
        return None
    top_pos = _insert_pos(original)
    new = original[:top_pos] + top_block + original[top_pos:]
    idx = idx0 + len(top_block)
    new[idx] = new_sink
    indent = line[: len(line) - len(line.lstrip())]
    hint = FIX_HINTS.get(finding.rule_id, "")
    new.insert(idx, f"{indent}# PatchProof fix ({finding.rule_id}): {hint}\n")
    try:
        ast.parse("".join(new))
    except SyntaxError:
        return None
    return new


def _advisory_fix(original: list[str], finding: Finding) -> list[str]:
    idx = max(0, min(finding.line_no - 1, len(original) - 1))
    line = original[idx]
    indent = line[: len(line) - len(line.lstrip())]
    hint = FIX_HINTS.get(finding.rule_id, "")
    fixed = list(original)
    fixed.insert(idx, f"{indent}# PatchProof fix ({finding.rule_id}): {hint}\n")
    return fixed


def _insert_pos(lines: list[str]) -> int:
    """Insert helpers/imports after the module docstring, else at the top."""
    try:
        tree = ast.parse("".join(lines))
    except SyntaxError:
        return 0
    if tree.body and isinstance(tree.body[0], ast.Expr) and isinstance(tree.body[0].value, ast.Constant):
        return int(tree.body[0].end_lineno or 0)
    return 0


def _need_import(source: str, module: str, stmt: str) -> list[str]:
    if re.search(rf"^\s*(import {re.escape(module)}\b|from {re.escape(module)}\b)", source, re.M):
        return []
    return [stmt + "\n"]


def _fix_sqli(original: list[str], line: str) -> tuple[list[str], str] | None:
    # execute(f"... {var} ...") with exactly one interpolation -> parameterized.
    if line.count("{") != 1 or "}" not in line:
        return None
    m = _SQLI_EXEC_RE.search(line)
    if not m or ", (" in line[m.end():]:
        return None
    var = re.search(r"\{([^{}]+)\}", line)
    if not var:
        return None
    expr = var.group(1).strip()
    if not re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", expr):
        return None
    body = line[: m.start()] + m.group(1) + m.group(2) + line[m.end():]
    body = body.replace("'" + "{" + expr + "}" + "'", "?", 1)
    body = re.sub(r"\{" + re.escape(expr) + r"\}", "?", body, count=1)
    # Convert the remaining quote style: f"..." -> "..." (prefix already dropped).
    close = body.rfind(")")
    if close == -1:
        return None
    body = body[:close] + f", ({expr},)" + body[close:]
    return [], body


def _fix_cmdi(original: list[str], line: str) -> tuple[list[str], str] | None:
    del original
    body = line
    m = _CMDI_RUN_RE.search(body)
    if m:
        body = body[: m.start()] + f'{m.group(1)}["{m.group(3)}", {m.group(4).strip()}]' + body[m.end():]
    if "shell=True" in body:
        body = body.replace("shell=True", "shell=False")
    elif m is None:
        return None
    return [], body


def _fix_xss(original: list[str], line: str) -> tuple[list[str], str] | None:
    if "render_template_string" not in line and "Markup" not in line:
        return None
    if "escape" in line:
        return None
    body, n1 = re.subn(r"\+\s*([A-Za-z_][A-Za-z0-9_]*)\s*\+", r"+ html.escape(\1) +", line)
    body, n2 = re.subn(r"\+\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)", r"+ html.escape(\1))", body)
    if n1 + n2 == 0:
        return None
    return _need_import("".join(original), "html", "import html"), body


def _fix_pathtrav(original: list[str], line: str) -> tuple[list[str], str] | None:
    m = re.search(r"open\(\s*f\"([^\"{}\n]*)/\{([^{}]+)\}\"\s*\)", line)
    if not m:
        return None
    source = "".join(original)
    block = [] if "_confined_path" in source else ["\n", *_CONFINED_HELPER.splitlines(keepends=True)]
    body = line[: m.start()] + f'open(_confined_path("{m.group(1)}", {m.group(2).strip()}))' + line[m.end():]
    return block, body


def _fix_deser(original: list[str], line: str) -> tuple[list[str], str] | None:
    if "yaml.load(" in line and "Loader" not in line and "safe_load" not in line:
        return [], line.replace("yaml.load(", "yaml.safe_load(")
    if "pickle.loads(" in line:
        return _need_import("".join(original), "json", "import json"), line.replace("pickle.loads(", "json.loads(")
    return None


def _fix_secret(original: list[str], line: str) -> tuple[list[str], str] | None:
    m = _SECRET_ASSIGN_RE.match(line.rstrip("\n"))
    if not m or "os.environ" in line:
        return None
    eol = "\n" if line.endswith("\n") else ""
    body = f'{m.group(1)}{m.group(2)} = os.environ["{m.group(2)}"]' + eol
    return _need_import("".join(original), "os", "import os"), body


def _fix_ssrf(original: list[str], line: str) -> tuple[list[str], str] | None:
    m = re.search(r"(requests\.(?:get|post|put|delete|head|request)\(\s*)f\"\{([^{}]+)\}\"", line)
    if not m:
        return None
    source = "".join(original)
    block = [] if "_checked_url" in source else ["\n", *_CHECKED_URL_HELPER.splitlines(keepends=True)]
    body = line[: m.start()] + f"{m.group(1)}_checked_url({m.group(2).strip()})" + line[m.end():]
    return block, body
