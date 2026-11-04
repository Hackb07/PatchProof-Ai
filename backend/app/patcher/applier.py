"""Apply unified diffs to a repo checkout.

Hunks are matched by content (context + removed lines), not just by line
number: after earlier patches shift a file, later hunks still land on the
right code instead of corrupting it.
"""
import re
from pathlib import Path

_HUNK_RE = re.compile(r"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@")

# How far (in lines) from a hunk's recorded position to search for its
# expected content before giving up.
_SEARCH_RADIUS = 80


def apply_diff(repo_path: str, diff: str) -> bool:
    """Apply a unified diff produced by the patcher. Returns True on success.

    Every hunk must match its expected old lines at (or near) the recorded
    position; a hunk that matches nowhere fails the whole application, so a
    stale diff can never silently rewrite the wrong code.
    """
    target_rel, hunks = _parse(diff)
    if not target_rel or not hunks:
        return False
    # Defense in depth: never write outside the checkout or through a link.
    if ".." in target_rel or Path(target_rel).is_absolute():
        return False
    target = Path(repo_path) / target_rel
    if target.is_symlink():
        return False
    try:
        lines = target.read_text(encoding="utf-8", errors="replace").splitlines(keepends=True)
    except OSError:
        return False
    # Apply bottom-up so earlier hunk positions stay valid; each hunk is
    # still content-verified before splicing.
    for hunk in sorted(hunks, key=lambda h: h[0], reverse=True):
        if not _apply_hunk(lines, hunk):
            return False
    target.write_text("".join(lines))
    return True


def _apply_hunk(lines: list[str], hunk: tuple[int, list[str], list[str]]) -> bool:
    start, old_lines, new_lines = hunk
    if not old_lines:
        idx = max(0, min(start - 1, len(lines)))
        lines[idx:idx] = new_lines
        return True
    expected = max(0, min(start - 1, len(lines)))
    if _matches_at(lines, expected, old_lines):
        lines[expected: expected + len(old_lines)] = new_lines
        return True
    # Search outward from the expected position: earlier patches may have
    # shifted the hunk's content.
    for dist in range(1, _SEARCH_RADIUS + 1):
        lo = max(0, expected - dist)
        if _matches_at(lines, lo, old_lines):
            lines[lo: lo + len(old_lines)] = new_lines
            return True
        hi = expected + dist
        if _matches_at(lines, hi, old_lines):
            lines[hi: hi + len(old_lines)] = new_lines
            return True
    return False


def _matches_at(lines: list[str], idx: int, old: list[str]) -> bool:
    if idx + len(old) > len(lines):
        return False
    return lines[idx: idx + len(old)] == old


def _parse(diff: str) -> tuple[str, list[tuple[int, list[str], list[str]]]]:
    target = ""
    hunks: list[tuple[int, list[str], list[str]]] = []
    current: tuple[int, list[str], list[str]] | None = None
    for line in diff.splitlines(keepends=True):
        if line.startswith("+++ b/"):
            target = line[len("+++ b/"):].strip()
        elif line.startswith("@@"):
            m = _HUNK_RE.match(line)
            if m:
                current = (int(m.group(1)), [], [])
                hunks.append(current)
        elif current is not None:
            if line.startswith("+") and not line.startswith("+++"):
                current[2].append(line[1:])
            elif line.startswith(" "):
                current[1].append(line[1:])
                current[2].append(line[1:])
            elif line.startswith("-") and not line.startswith("---"):
                current[1].append(line[1:])
            # `\ No newline at end of file` markers carry no content.
    return target, hunks
