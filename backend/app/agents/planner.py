"""Planner agent: orchestrates scan -> triage -> risk -> repro -> validate -> patch -> verify."""
import datetime
import shutil
from pathlib import Path

from git import Repo

from .. import store
from ..config import settings
from ..models import Evidence, Scan
from ..patcher.generator import generate_patches
from ..sandbox.runner import reproduce
from ..scanner.scan import scan_repo
from ..verifier.verify import verify_patches
from .detector import triage
from .risk_assessor import assess
from .validator import validate


def run_pipeline(scan_id: str) -> None:
    session = store.SessionLocal()
    try:
        scan = session.get(Scan, scan_id)
        if scan is None:
            return
        scan.status = "scanning"
        session.commit()

        repo_path = _prepare_repo(session, scan)
        scan_repo(session, scan_id, repo_path)

        scan.status = "triaging"
        session.commit()
        triage(session, scan_id)
        assess(session, scan_id)

        scan.status = "patching"
        session.commit()
        reproduce(session, scan_id)
        validate(session, scan_id)
        generate_patches(session, scan_id, repo_path)

        scan.status = "verifying"
        session.commit()
        verify_patches(session, scan_id, repo_path)

        scan.status = "done"
        scan.finished_at = datetime.datetime.now(datetime.timezone.utc)
        session.add(Evidence(scan_id=scan_id, stage="done", actor="planner",
                             message="Pipeline complete: scan, triage, risk, repro, patch, verify"))
        session.commit()
    except Exception as exc:
        scan = session.get(Scan, scan_id)
        if scan is not None:
            scan.status = "failed"
            scan.error = str(exc)[:2000]
            session.add(Evidence(scan_id=scan_id, stage="done", actor="planner", message=f"Pipeline failed: {exc}"))
            session.commit()
    finally:
        session.close()


def _prepare_repo(session, scan: Scan) -> str:
    root = Path(settings.repo_root)
    root.mkdir(parents=True, exist_ok=True)
    dest = root / scan.id
    url = scan.repo_url.strip()
    # Local path support for fixtures/demo: file:// or absolute path copies instead of cloning.
    local = url[7:] if url.startswith("file://") else url
    if Path(local).exists() and Path(local).is_dir():
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(local, dest, ignore=shutil.ignore_patterns(".git", "__pycache__", ".venv"))
        scan.repo_path = str(dest)
        session.add(Evidence(scan_id=scan.id, stage="clone", actor="planner",
                             message=f"Local repo copied from {local}"))
        session.commit()
        return str(dest)
    if dest.exists():
        shutil.rmtree(dest)
    branch_kwargs = {} if scan.branch in ("", "HEAD") else {"branch": scan.branch}
    Repo.clone_from(url, dest, depth=1, **branch_kwargs)
    scan.repo_path = str(dest)
    session.add(Evidence(scan_id=scan.id, stage="clone", actor="planner",
                         message=f"Cloned {url} ({scan.branch})"))
    session.commit()
    return str(dest)
