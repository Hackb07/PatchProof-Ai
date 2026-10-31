"""Apply unified diffs to a repo checkout (MVP: single-file, single-hunk friendly)."""
import re
from pathlib import Path

_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@", re.M)


def apply_diff(repo_path: str, diff: str) -> bool:
    """Apply a unified diff produced by the patcher. Returns True on success."""
    target_rel, hunks = _parse(diff)
    if not target_rel or not hunks:
        return False
    target = Path(repo_path) / target_rel
    try:
        lines = target.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
    except OSError:
        return False
    # Apply hunks in reverse so line numbers stay valid.
    for start, old_count, new_lines in sorted(hunks, reverse=True):
        idx = max(0, start - 1)
        lines[idx: idx + old_count] = new_lines
    target.write_text("".join(lines))
    return True


def _parse(diff: str) -> tuple[str, list[tuple[int, int, list[str]]]]:
    target = ""
    hunks: list[tuple[int, int, list[str]]] = []
    current: tuple[int, int, list[str]] | None = None
    for line in diff.splitlines(keepends=True):
        if line.startswith("+++ b/"):
            target = line[len("+++ b/"):].strip()
        elif line.startswith("@@"):
            m = _HUNK_RE.match(line)
            if m:
                start = int(m.group(1))
                old_count = int(m.group(2) or "1")
                current = (start, old_count, [])
                hunks.append(current)
        elif current is not None:
            if line.startswith("+") and not line.startswith("+++"):
                current[2].append(line[1:])
            elif line.startswith(" ") or line.startswith("\\"):
                current[2].append(line[1:] if line.startswith(" ") else "")
            elif line.startswith("-") and not line.startswith("---"):
                pass  # removed line: skip (old_count already accounts for it)
    return target, hunks
