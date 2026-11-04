"""Validator agent: confirms findings using repro evidence + code context."""
from sqlalchemy.orm import Session

from ..models import Evidence, Finding
from .base import LLMClient


def _is_false_positive(output: str) -> bool:
    """Parse `VERDICT: TRUE_POSITIVE|FALSE_POSITIVE`, preferring an explicitly
    labeled line so free-text mentions can't flip the verdict. Unlabeled
    replies confirm the finding (matching the mock)."""
    for line in output.splitlines():
        upper = line.upper()
        if upper.startswith("VERDICT:"):
            return "FALSE_POSITIVE" in upper[len("VERDICT:"):]
    return False


def validate(session: Session, scan_id: str) -> list[Finding]:
    findings = session.query(Finding).filter_by(scan_id=scan_id).all()
    llm = LLMClient()
    for f in findings:
        reply = llm.chat(
            "You validate security findings. Reply VERDICT: TRUE_POSITIVE or VERDICT: FALSE_POSITIVE with REASON.",
            f"{f.title} at {f.file_path}:{f.line_no}\n{f.snippet}\n"
            f"Reproduced: {f.reproduced}. Repro log:\n{f.repro_log[:1500]}",
        ).output
        if _is_false_positive(reply):
            f.validated = False
            f.false_positive = True
        else:
            f.validated = True
            f.false_positive = False
    session.add(Evidence(scan_id=scan_id, stage="triage", actor="validator",
                         message="Validation pass complete"))
    session.commit()
    return findings
