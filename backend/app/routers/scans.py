"""Scan endpoints: submit repo, poll status, fetch full evidence report."""
from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.orm import Session, selectinload

from ..agents.planner import run_pipeline
from ..models import Scan
from ..schemas import EvidenceOut, FindingOut, PatchOut, ScanCreate, ScanOut, VerificationOut
from ..store import get_session, init_db

router = APIRouter(prefix="/api/scans", tags=["scans"])


@router.post("", response_model=ScanOut)
def create_scan(payload: ScanCreate, background: BackgroundTasks, session: Session = Depends(get_session)):
    init_db()
    scan = Scan(repo_url=payload.repo_url, branch=payload.branch or "HEAD", status="queued")
    session.add(scan)
    session.commit()
    session.refresh(scan)
    background.add_task(run_pipeline, scan.id)
    return _serialize(session, scan.id)


@router.get("", response_model=list[ScanOut])
def list_scans(session: Session = Depends(get_session)):
    init_db()
    scans = session.query(Scan).order_by(Scan.created_at.desc()).limit(50).all()
    return [_serialize(session, s.id) for s in scans]


@router.get("/{scan_id}", response_model=ScanOut)
def get_scan(scan_id: str, session: Session = Depends(get_session)):
    scan = session.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="scan not found")
    return _serialize(session, scan_id)


@router.post("/{scan_id}/rerun", response_model=ScanOut)
def rerun_scan(scan_id: str, background: BackgroundTasks, session: Session = Depends(get_session)):
    scan = session.get(Scan, scan_id)
    if scan is None:
        raise HTTPException(status_code=404, detail="scan not found")
    scan.status = "queued"
    scan.error = ""
    session.commit()
    background.add_task(run_pipeline, scan.id)
    return _serialize(session, scan.id)


def _serialize(session: Session, scan_id: str) -> ScanOut:
    scan = (
        session.query(Scan)
        .options(selectinload(Scan.findings), selectinload(Scan.evidence))
        .filter_by(id=scan_id)
        .one()
    )
    findings: list[FindingOut] = []
    for f in sorted(scan.findings, key=lambda x: (-x.risk_score, x.file_path, x.line_no)):
        patches = [
            PatchOut(
                id=p.id, diff=p.diff, summary=p.summary, applied=p.applied,
                verifications=[
                    VerificationOut(
                        id=v.id, status=v.status, rescan_clean=v.rescan_clean,
                        tests_passed=v.tests_passed, test_log=v.test_log, notes=v.notes,
                    )
                    for v in p.verifications
                ],
            )
            for p in f.patches
        ]
        findings.append(FindingOut(
            id=f.id, rule_id=f.rule_id, title=f.title, cwe=f.cwe, severity=f.severity,
            confidence=f.confidence, file_path=f.file_path, line_no=f.line_no,
            snippet=f.snippet, explanation=f.explanation, risk_score=f.risk_score,
            risk_rationale=f.risk_rationale, reproduced=f.reproduced,
            repro_log=f.repro_log, validated=f.validated,
            false_positive=f.false_positive, patches=patches,
        ))
    evidence = [EvidenceOut(id=e.id, stage=e.stage, actor=e.actor, message=e.message, ref_id=e.ref_id)
                for e in sorted(scan.evidence, key=lambda x: str(x.created_at))]
    return ScanOut(id=scan.id, repo_url=scan.repo_url, branch=scan.branch,
                   status=scan.status, error=scan.error, findings=findings, evidence=evidence)
