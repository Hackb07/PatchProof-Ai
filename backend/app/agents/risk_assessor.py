"""Risk assessor agent: scores each finding 0-10 with rationale."""
import re

from sqlalchemy.orm import Session

from ..models import Evidence, Finding
from .base import LLMClient

SEVERITY_PRIOR = {"critical": 9.0, "high": 7.5, "medium": 5.0, "low": 2.5}


def assess(session: Session, scan_id: str) -> list[Finding]:
    findings = session.query(Finding).filter_by(scan_id=scan_id).all()
    llm = LLMClient()
    for f in findings:
        if llm.mock:
            # Offline heuristic: severity prior adjusted by confidence, no fake precision.
            score = SEVERITY_PRIOR.get(f.severity, 5.0)
            if f.confidence == "low":
                score = max(1.0, score - 1.5)
            elif f.confidence == "high":
                score = min(10.0, score + 0.5)
            reply = (f"RISK_SCORE: {score}\nRATIONALE: Mock heuristic: {f.severity} severity, "
                     f"{f.confidence} confidence, {f.cwe}. Connect a Meta model for contextual scoring.")
        else:
            reply = llm.chat(
                "You are a security risk assessor. Reply with RISK_SCORE: <0-10> and RATIONALE: <one paragraph>.",
                f"Severity {f.severity} confidence {f.confidence}. {f.title} ({f.cwe}) "
                f"at {f.file_path}:{f.line_no}\n{f.snippet}\n{f.explanation}",
            ).output
            parsed = _parse_score(reply)
            score = parsed if parsed is not None else SEVERITY_PRIOR.get(f.severity, 5.0)
            if f.confidence == "low":
                score = max(1.0, score - 1.5)
        f.risk_score = round(max(0.0, min(10.0, score)), 1)
        f.risk_rationale = reply.strip()[:2000]
    session.add(Evidence(scan_id=scan_id, stage="risk", actor="risk-assessor",
                         message=f"Risk scoring complete for {len(findings)} findings"))
    session.commit()
    return findings


def _parse_score(text: str) -> float | None:
    m = re.search(r"RISK_SCORE:\s*([0-9]+(?:\.[0-9]+)?)", text.upper())
    if not m:
        return None
    try:
        return float(m.group(1))
    except ValueError:
        return None
