"""Detector/triage agent: dedupes and filters raw scanner findings."""
from sqlalchemy.orm import Session

from ..models import Evidence, Finding
from .base import LLMClient


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
        if "DROP" in verdict.upper():
            session.delete(f)
        else:
            kept.append(f)
    session.add(Evidence(scan_id=scan_id, stage="triage", actor="detector",
                         message=f"Triage complete: {len(kept)}/{len(findings)} findings kept"))
    session.commit()
    return kept
