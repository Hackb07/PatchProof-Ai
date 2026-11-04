"""Walk a repo checkout and persist findings."""
from pathlib import Path

from sqlalchemy.orm import Session

from ..models import Evidence, Finding
from .rules import scan_source

SKIP_DIRS = {".git", ".venv", "venv", "__pycache__", "node_modules", ".tox"}


def scan_repo(session: Session, scan_id: str, repo_path: str) -> list[Finding]:
    root = Path(repo_path)
    created: list[Finding] = []
    for path in sorted(root.rglob("*.py")):
        if any(part in SKIP_DIRS for part in path.parts):
            continue
        # Never follow symlinks out of the checkout: a hostile repo could
        # otherwise link `evil.py` at a host file outside it.
        if path.is_symlink():
            continue
        try:
            source = path.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(path.relative_to(root))
        for raw in scan_source(source, rel):
            finding = Finding(
                scan_id=scan_id,
                rule_id=raw["rule_id"],
                title=raw["title"],
                cwe=raw["cwe"],
                severity=raw["severity"],
                confidence=raw["confidence"],
                file_path=rel,
                line_no=raw["line_no"],
                snippet=raw["snippet"],
                explanation=raw["explanation"],
            )
            session.add(finding)
            created.append(finding)
    session.add(Evidence(scan_id=scan_id, stage="scan", actor="detector",
                         message=f"Static scan complete: {len(created)} raw findings"))
    session.commit()
    return created
