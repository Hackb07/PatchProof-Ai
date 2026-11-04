"""GitHub helper endpoints: import + file view."""
from pathlib import Path

from fastapi import APIRouter, BackgroundTasks, Depends, HTTPException
from sqlalchemy.orm import Session

from ..agents.planner import run_pipeline
from ..models import Scan
from ..store import get_session, init_db

router = APIRouter(prefix="/api/github", tags=["github"])

# Upper bound on bytes pulled off disk for the file viewer (decoded and
# truncated to 100k chars afterwards).
_MAX_FILE_BYTES = 110_000


@router.post("/import")
def import_repo(payload: dict, background: BackgroundTasks, session: Session = Depends(get_session)):
    init_db()
    url = str(payload.get("repo_url", "")).strip()
    if not url:
        raise HTTPException(status_code=422, detail="repo_url required")
    if len(url) > 2048:
        raise HTTPException(status_code=422, detail="repo_url too long")
    branch = str(payload.get("branch", "HEAD") or "").strip() or "HEAD"
    if len(branch) > 256:
        raise HTTPException(status_code=422, detail="branch too long")
    scan = Scan(repo_url=url, branch=branch, status="queued")
    session.add(scan)
    session.commit()
    session.refresh(scan)
    # Queue the pipeline in the background and return immediately for
    # polling; running it inline would hang the request for minutes.
    background.add_task(run_pipeline, scan.id)
    return {"scan_id": scan.id, "status": scan.status}


@router.get("/file")
def read_file(scan_id: str, path: str, session: Session = Depends(get_session)):
    scan = session.get(Scan, scan_id)
    if scan is None or not scan.repo_path:
        raise HTTPException(status_code=404, detail="scan or repo not found")
    try:
        target = (Path(scan.repo_path) / path).resolve()
        target.relative_to(Path(scan.repo_path).resolve())
    except (OSError, ValueError):
        raise HTTPException(status_code=404, detail="file not found")
    if not target.is_file():
        raise HTTPException(status_code=404, detail="file not found")
    # Bounded read: a huge file in a scanned repo must not OOM the server.
    try:
        with target.open("rb") as fh:
            raw = fh.read(_MAX_FILE_BYTES)
    except OSError:
        raise HTTPException(status_code=404, detail="file not found")
    content = raw.decode("utf-8", errors="replace")
    return {"scan_id": scan_id, "path": path, "content": content[:100000]}
