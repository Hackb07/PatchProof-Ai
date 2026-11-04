"""Minimal patch generation: deterministic per-rule transforms.

The deterministic transforms below guarantee the MVP always produces a
safe, reviewable diff even offline (LLM_MOCK=1). Every transform is
validated with ast.parse — if a real fix does not apply cleanly, the
patcher falls back to an advisory comment so the diff can never break
the file's syntax.
"""
import ast
import difflib
import re
from pathlib import Path

from sqlalchemy.orm import Session

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
    root = _PPPath(base).resolve()
    p = (root / name).resolve()
    try:
        p.relative_to(root)
    except ValueError:
        raise ValueError("path escapes base directory")
    return str(p)


'''

_CHECKED_URL_HELPER = '''import ipaddress as _pp_ip
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


'''

_SECRET_ASSIGN_RE = re.compile(r"^(\s*)([A-Za-z_][A-Za-z0-9_]*)\s*=\s*(['\"]).*?\3\s*(#.*)?$")
_SQLI_EXEC_RE = re.compile(r"(\.execute(?:many|script)?\(\s*)f([\"'])")
_CMDI_RUN_RE = re.compile(r"(subprocess\.\w+\(\s*)f([\"'])(.*?)\{([^{}]+)\}(.*?)\2")
_CMDI_LIST_ARG_RE = re.compile(r"subprocess\.\w+\(\s*\[")


def generate_patches(session: Session, scan_id: str, repo_path: str) -> list[Patch]:
    findings = session.query(Finding).filter_by(scan_id=scan_id, false_positive=False).all()
    patches: list[Patch] = []
    for f in findings:
        hint = FIX_HINTS.get(f.rule_id, "Apply the minimal safe fix.")
        diff, summary = _deterministic_fix(repo_path, f, hint)
        patch = Patch(finding_id=f.id, diff=diff, summary=summary, applied=False)
        session.add(patch)
        session.flush()  # assign patch.id for the evidence ref
        session.add(Evidence(scan_id=scan_id, stage="patch", actor="patcher",
                             message=f"Patch {patch.id} for {f.rule_id} at {f.file_path}:{f.line_no}",
                             ref_id=patch.id))
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

    real = _apply_real_fix(original, finding)
    if real is None:
        fixed, top_pos, top_len, sink_idx = _advisory_fix(original, finding)
        summary = f"Advisory patch for {finding.rule_id} at line {finding.line_no}: {hint}"
    else:
        fixed, top_pos, top_len, sink_idx = real
        summary = f"Minimal fix for {finding.rule_id} at line {finding.line_no}: {hint}"
    diff = _structured_diff(original, fixed, top_pos, top_len, sink_idx, finding.file_path)
    return diff, summary


def _apply_real_fix(original: list[str], finding: Finding) -> tuple[list[str], int, int, int] | None:
    """Full-file transform plus its layout, or None when no safe transform
    matches. Returns (fixed, top_pos, top_len, sink_idx0)."""
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
    return new, top_pos, len(top_block), idx0


def _advisory_fix(original: list[str], finding: Finding) -> tuple[list[str], int, int, int]:
    idx = max(0, min(finding.line_no - 1, len(original) - 1))
    line = original[idx]
    indent = line[: len(line) - len(line.lstrip())]
    hint = FIX_HINTS.get(finding.rule_id, "")
    fixed = list(original)
    fixed.insert(idx, f"{indent}# PatchProof fix ({finding.rule_id}): {hint}\n")
    return fixed, 0, 0, idx


_DIFF_CTX = 3


def _structured_diff(original: list[str], fixed: list[str], top_pos: int, top_len: int,
                     sink_idx: int, file_path: str) -> str:
    """Structured unified diff: one hunk for the top-of-file helper/import
    insertion (if any) plus one hunk for the sink change. Small local hunks
    keep sequential application working — a single hunk spanning the whole
    file would embed other (already patched) sinks in its context."""
    if original == fixed:
        return ""
    fixed_sink_start = sink_idx + top_len
    fixed_sink_end = len(fixed) - (len(original) - (sink_idx + 1))
    if top_pos > len(original) or fixed_sink_end < fixed_sink_start or fixed_sink_end > len(fixed):
        return _spanning_diff(original, fixed, file_path)
    top_block = fixed[top_pos: top_pos + top_len]
    sink_new = fixed[fixed_sink_start: fixed_sink_end]

    # Top hunk uses below-only context so stacked top insertions from
    # earlier patches still match by content.
    top_ctx_end = min(top_pos + _DIFF_CTX, len(original))
    sink_start = max(0, sink_idx - _DIFF_CTX)
    sink_end = min(sink_idx + 1 + _DIFF_CTX, len(original))
    if top_len > 0 and sink_start < top_ctx_end:
        return _spanning_diff(original, fixed, file_path)

    out = [f"--- a/{file_path}\n", f"+++ b/{file_path}\n"]
    added_before = 0
    if top_len > 0:
        old = original[top_pos: top_ctx_end]
        new = list(top_block) + old
        out += _render_added_first(top_pos, old, new)
        added_before += top_len
    old = original[sink_start: sink_end]
    new = original[sink_start: sink_idx] + sink_new + original[sink_idx + 1: sink_end]
    out += _render_replace_middle(sink_start, old, new, added_before, sink_idx - sink_start)
    return "".join(out)


def _render_added_first(old_start0: int, old: list[str], new: list[str]) -> list[str]:
    lines = [f"@@ -{old_start0 + 1},{len(old)} +{old_start0 + 1},{len(new)} @@\n"]
    for line in new[: len(new) - len(old)]:
        lines.append("+" + line if line.endswith("\n") else "+" + line + "\n")
    for line in old:
        lines.append(" " + line if line.endswith("\n") else " " + line + "\n")
    return lines


def _render_replace_middle(old_start0: int, old: list[str], new: list[str],
                           added_before: int, pre_len: int) -> list[str]:
    new_start0 = old_start0 + added_before
    lines = [f"@@ -{old_start0 + 1},{len(old)} +{new_start0 + 1},{len(new)} @@\n"]
    new_mid_len = len(new) + 1 - len(old)
    for line in old[:pre_len]:
        lines.append(" " + line if line.endswith("\n") else " " + line + "\n")
    for line in old[pre_len: pre_len + 1]:
        lines.append("-" + line if line.endswith("\n") else "-" + line + "\n")
    for line in new[pre_len: pre_len + new_mid_len]:
        lines.append("+" + line if line.endswith("\n") else "+" + line + "\n")
    for line in old[pre_len + 1:]:
        lines.append(" " + line if line.endswith("\n") else " " + line + "\n")
    return lines


def _spanning_diff(original: list[str], fixed: list[str], file_path: str) -> str:
    """Single-diff fallback for overlapping change regions."""
    return "".join(difflib.unified_diff(
        original, fixed, fromfile=f"a/{file_path}", tofile=f"b/{file_path}"))


def _insert_pos(lines: list[str]) -> int:
    """Insert helpers/imports after the shebang, encoding cookie, module
    docstring, and `from __future__` imports (which must stay first)."""
    try:
        tree = ast.parse("".join(lines))
    except SyntaxError:
        tree = None
    idx = 0
    if lines and lines[0].startswith("#!"):
        idx = 1
    for i in range(idx, min(idx + 2, len(lines))):
        if "coding:" in lines[i] or "coding=" in lines[i]:
            idx = i + 1
            break
    if tree is not None and tree.body and isinstance(tree.body[0], ast.Expr) and isinstance(tree.body[0].value, ast.Constant):
        idx = max(idx, int(tree.body[0].end_lineno or 0))
    # __future__ imports must precede all other code.
    j = idx
    while j < len(lines):
        stripped = lines[j].strip()
        if not stripped:
            j += 1
            continue
        if stripped.startswith("from __future__ import "):
            idx = j + 1
            j += 1
            continue
        break
    return min(idx, len(lines))


def _need_import(source: str, module: str, stmt: str) -> list[str]:
    # Only `import <module>` (without `as`) binds the plain module name;
    # `from <module> import ...` and `import <module> as ...` do not.
    for line in source.splitlines():
        rest = line.lstrip()
        if rest.startswith("import "):
            names = rest[len("import "):].split("#", 1)[0]
            for part in names.split(","):
                part = part.strip()
                if part == module or part.startswith(module + "."):
                    return []
    return [stmt + "\n"]


def _find_matching_paren(s: str, open_idx: int) -> int | None:
    """Index of the `)` matching the `(` at `open_idx` (quote-aware; bails
    at a `#` comment since no code paren can follow it)."""
    if open_idx >= len(s) or s[open_idx] != "(":
        return None
    depth = 0
    quote = None
    i = open_idx
    while i < len(s):
        ch = s[i]
        if quote is not None:
            if ch == "\\":
                i += 2
                continue
            if ch == quote:
                quote = None
        elif ch in ("'", '"'):
            quote = ch
        elif ch == "(":
            depth += 1
        elif ch == ")":
            depth -= 1
            if depth == 0:
                return i
        elif ch == "#":
            return None
        i += 1
    return None


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
    # Drop quotes around the placeholder: '{x}' or "{x}" becomes ?.
    single = "'" + "{" + expr + "}" + "'"
    double = '"' + "{" + expr + "}" + '"'
    if single in body:
        body = body.replace(single, "?", 1)
    elif double in body:
        body = body.replace(double, "?", 1)
    else:
        body = body.replace("{" + expr + "}", "?", 1)
    # Append the parameter tuple at the end of the execute(...) call,
    # located by paren matching so trailing-comment parens can't mislead it.
    exec_pos = body.find("execute")
    if exec_pos == -1:
        return None
    open_idx = exec_pos + len("execute")
    while open_idx < len(body) and (body[open_idx].isalnum() or body[open_idx] == "_"):
        open_idx += 1
    while open_idx < len(body) and body[open_idx] in " \t":
        open_idx += 1
    if open_idx >= len(body) or body[open_idx] != "(":
        return None
    close = _find_matching_paren(body, open_idx)
    if close is None:
        return None
    body = body[:close] + f", ({expr},)" + body[close:]
    return [], body


def _fix_cmdi(original: list[str], line: str) -> tuple[list[str], str] | None:
    del original
    m = _CMDI_RUN_RE.search(line)
    if m:
        before, var, after = m.group(3), m.group(4).strip(), m.group(5)
        # Exactly one simple interpolation; anything else gets advice.
        if ("{" not in before and "}" not in before
                and "{" not in after and "}" not in after
                and '"' not in before and "'" not in before and "\\" not in before
                and '"' not in after and "'" not in after and "\\" not in after
                and re.fullmatch(r"[A-Za-z_][A-Za-z0-9_]*", var)):
            argv = [f'"{t}"' for t in before.split()] + [var] + [f'"{t}"' for t in after.split()]
            body = line[: m.start()] + f'{m.group(1)}[{", ".join(argv)}]' + line[m.end():]
            return [], body.replace("shell=True", "shell=False")
    # A bare shell flip is only safe when the command is already an argv
    # list; flipping a plain string would break the call at runtime.
    if "shell=True" in line and _CMDI_LIST_ARG_RE.search(line):
        return [], line.replace("shell=True", "shell=False")
    return None


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
    if "pickle.load(" in line:
        return _need_import("".join(original), "json", "import json"), line.replace("pickle.load(", "json.load(")
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
