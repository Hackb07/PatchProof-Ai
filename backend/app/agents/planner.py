"""Planner agent: orchestrates scan -> triage -> risk -> repro -> validate -> patch -> verify."""
import datetime
import shutil
import subprocess
from pathlib import Path

from .. import store
from ..config import is_local_scan_repo, normalize_local_path, settings
from ..models import Evidence, Scan
from ..patcher.generator import generate_patches
from ..sandbox.runner import reproduce
from ..scanner.scan import scan_repo
from ..verifier.verify import verify_patches
from .detector import triage
from .risk_assessor import assess
from .validator import validate

_COPY_IGNORE = {".git", "__pycache__", ".venv", "venv", "node_modules", ".tox"}


def _utcnow() -> datetime.datetime:
    return datetime.datetime.now(datetime.timezone.utc)


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
        scan.finished_at = _utcnow()
        session.add(Evidence(scan_id=scan_id, stage="done", actor="planner",
                             message="Pipeline complete: scan, triage, risk, repro, patch, verify"))
        session.commit()
    except Exception as exc:
        scan = session.get(Scan, scan_id)
        if scan is not None:
            scan.status = "failed"
            scan.error = str(exc)[:2000]
            scan.finished_at = _utcnow()
            session.add(Evidence(scan_id=scan_id, stage="done", actor="planner", message=f"Pipeline failed: {exc}"))
            session.commit()
    finally:
        session.close()


def _copy_ignore(path: str, names: list[str]) -> set[str]:
    # Skip vendored dirs and symlinks (which could point outside the tree).
    ignored = {n for n in names if n in _COPY_IGNORE}
    for n in names:
        if (Path(path) / n).is_symlink():
            ignored.add(n)
    return ignored


def _prepare_repo(session, scan: Scan) -> str:
    root = Path(settings.repo_root)
    root.mkdir(parents=True, exist_ok=True)
    dest = root / scan.id
    url = scan.repo_url.strip()
    # Local path support for fixtures/demo: file:// or plain path copies
    # instead of cloning.
    if is_local_scan_repo(url):
        local = normalize_local_path(url)
        if dest.exists():
            shutil.rmtree(dest)
        shutil.copytree(local, dest, ignore=_copy_ignore)
        scan.repo_path = str(dest)
        session.add(Evidence(scan_id=scan.id, stage="clone", actor="planner",
                             message=f"Local repo copied from {local}"))
        session.commit()
        return str(dest)
    if dest.exists():
        shutil.rmtree(dest)
    branch = (scan.branch or "").strip()
    cmd = ["git", "clone", "--depth", "1"]
    if branch and branch != "HEAD":
        cmd += ["--branch", branch]
    # `--` keeps a hostile URL from being parsed as git options.
    cmd += ["--", url, str(dest)]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
    except subprocess.TimeoutExpired:
        raise RuntimeError("git clone timed out after 120s")
    if proc.returncode != 0:
        raise RuntimeError(f"git clone failed: {proc.stderr.strip()}")
    scan.repo_path = str(dest)
    session.add(Evidence(scan_id=scan.id, stage="clone", actor="planner",
                         message=f"Cloned {url} ({scan.branch})"))
    session.commit()
    return str(dest)
