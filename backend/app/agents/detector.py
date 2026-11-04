"""Detector/triage agent: dedupes and filters raw scanner findings."""
from sqlalchemy.orm import Session

from ..models import Evidence, Finding
from .base import LLMClient


def _keep_verdict(output: str) -> bool:
    """Parse `TRIAGE: KEEP|DROP`, preferring an explicitly labeled line so a
    free-text mention of "drop" (e.g. "do not drop this") can't discard a
    finding. Unlabeled replies keep the finding (matching the mock)."""
    for line in output.splitlines():
        upper = line.upper()
        if upper.startswith("TRIAGE:"):
            return "DROP" not in upper[len("TRIAGE:"):]
    return True


def triage(session: Session, scan_id: str) -> list[Finding]:
    findings = session.query(Finding).filter_by(scan_id=scan_id).all()
    llm = LLMClient()
    kept: list[Finding] = []
    seen: set[tuple[str, str, int]] = set()
    for f in findings:
        key = (f.rule_id, f.file_path, f.line_no)
        if key in seen:
            session.delete(f)
            continue
        seen.add(key)
        verdict = llm.chat(
            "You triage static-analysis findings. Reply TRIAGE: KEEP or TRIAGE: DROP with a reason.",
            f"Rule {f.rule_id} {f.title} at {f.file_path}:{f.line_no}\n{f.snippet}\n{f.explanation}",
        ).output
        if _keep_verdict(verdict):
            kept.append(f)
        else:
            session.delete(f)
    session.add(Evidence(scan_id=scan_id, stage="triage", actor="detector",
                         message=f"Triage complete: {len(kept)}/{len(findings)} findings kept"))
    session.commit()
    return kept
