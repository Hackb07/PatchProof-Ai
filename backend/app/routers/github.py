"""GitHub helper endpoints: import + file view."""
from pathlib import Path

from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.orm import Session

from ..models import Scan
from ..store import get_session

router = APIRouter(prefix="/api/github", tags=["github"])


@router.post("/import")
def import_repo(payload: dict, session: Session = Depends(get_session)):
    url = str(payload.get("repo_url", "")).strip()
    if not url:
        raise HTTPException(status_code=422, detail="repo_url required")
    scan = Scan(repo_url=url, branch=str(payload.get("branch", "HEAD")), status="queued")
    session.add(scan)
    session.commit()
    session.refresh(scan)
    # Run inline import only (clone happens in pipeline); return the scan id for polling.
    from ..agents.planner import run_pipeline

    run_pipeline(scan.id)
    updated = session.get(Scan, scan.id)
    assert updated is not None
    return {"scan_id": updated.id, "status": updated.status}


@router.get("/file")
def read_file(scan_id: str, path: str, session: Session = Depends(get_session)):
    scan = session.get(Scan, scan_id)
    if scan is None or not scan.repo_path:
        raise HTTPException(status_code=404, detail="scan or repo not found")
    target = (Path(scan.repo_path) / path).resolve()
    root = Path(scan.repo_path).resolve()
    if not str(target).startswith(str(root)) or not target.is_file():
        raise HTTPException(status_code=404, detail="file not found")
    content = target.read_text(encoding="utf-8", errors="replace")
    return {"scan_id": scan_id, "path": path, "content": content[:100000]}
