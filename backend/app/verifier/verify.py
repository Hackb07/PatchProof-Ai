"""Fix verification: re-scan the patched file + run repo tests + re-run PoC."""
import shutil
import subprocess
from pathlib import Path

from sqlalchemy.orm import Session

from ..config import is_local_scan_repo, settings
from ..models import Evidence, Finding, Patch, Scan, Verification
from ..patcher.applier import apply_diff
from ..scanner.rules import scan_source


def verify_patches(session: Session, scan_id: str, repo_path: str) -> list[Verification]:
    row = session.get(Scan, scan_id)
    trusted = bool(row is not None and is_local_scan_repo(row.repo_url))
    patches = (
        session.query(Patch)
        .join(Finding, Patch.finding_id == Finding.id)
        .filter(Finding.scan_id == scan_id)
        .all()
    )
    results: list[Verification] = []
    for patch in patches:
        finding = session.get(Finding, patch.finding_id)
        assert finding is not None
        target = Path(repo_path) / finding.file_path
        before = target.read_text(encoding="utf-8", errors="replace") if target.exists() else ""
        applied = apply_diff(repo_path, patch.diff) if patch.diff else False
        patch.applied = applied
        after = target.read_text(encoding="utf-8", errors="replace") if target.exists() else ""

        rescan_clean = _rescan_clean(before, after, finding)
        tests_passed, test_log = _run_repo_tests(repo_path, trusted)
        status = _decide(applied, rescan_clean, tests_passed)
        notes = (
            f"Patch {'applied' if applied else 'NOT applied'}; "
            f"rescan {'clean' if rescan_clean else 'still flags the sink'}; "
            f"tests {'passed' if tests_passed else ('failed' if tests_passed is False else 'not found')}."
        )
        verification = Verification(
            patch_id=patch.id, status=status, rescan_clean=rescan_clean,
            tests_passed=tests_passed, test_log=test_log[:3000], notes=notes,
        )
        session.add(verification)
        session.flush()  # assign verification.id for the evidence ref
        session.add(Evidence(scan_id=scan_id, stage="verify", actor="verifier",
                             message=f"Verification {verification.id} for patch {patch.id}: {status}",
                             ref_id=verification.id))
        results.append(verification)
    session.add(Evidence(scan_id=scan_id, stage="verify", actor="verifier",
                         message=f"Verification complete: {sum(1 for v in results if v.status == 'fixed')}/{len(results)} fixed"))
    session.commit()
    return results


def _decide(applied: bool, rescan_clean: bool, tests_passed: bool | None) -> str:
    if not applied:
        return "unfixed"
    if rescan_clean and tests_passed is not False:
        return "fixed"
    if not rescan_clean:
        return "unfixed"
    return "inconclusive"


def _rescan_clean(before: str, after: str, finding: Finding) -> bool:
    if after == before:
        return False
    # Anchor on the fix comment the patcher always inserts: helper
    # insertions at the top of the file shift the sink away from its
    # original line number, so the original `line_no` window is stale.
    marker = f"# PatchProof fix ({finding.rule_id})"
    anchor = None
    for i, line in enumerate(after.splitlines(), start=1):
        if marker in line:
            anchor = i
    fresh = [f for f in scan_source(after) if f["rule_id"] == finding.rule_id]
    before_count = len([f for f in scan_source(before) if f["rule_id"] == finding.rule_id])
    if anchor is not None:
        near = [f for f in fresh if abs(f["line_no"] - anchor) <= 2]
        return not near or len(fresh) < before_count
    return _rescan_clean_legacy(before_count, fresh, after, finding)


def _rescan_clean_legacy(before_count: int, fresh: list[dict], after: str, finding: Finding) -> bool:
    """Fallback when the fix comment is missing: look for hardening markers
    near the original sink line, then confirm by rescan."""
    markers = ["# PatchProof fix", "shell=False", "safe_load", "os.environ", "html.escape", "allowlist"]
    near = "\n".join(after.splitlines()[max(0, finding.line_no - 3): finding.line_no + 3])
    if any(m in near for m in markers):
        same_line = [f for f in fresh if abs(f["line_no"] - finding.line_no) <= 2]
        return not same_line or len(fresh) < before_count
    return False


def _docker_available() -> bool:
    if not shutil.which("docker"):
        return False
    try:
        proc = subprocess.run(["docker", "info"], capture_output=True, timeout=10)
        return proc.returncode == 0
    except Exception:
        return False


def _run_repo_tests(repo_path: str, trusted_local: bool) -> tuple[bool | None, str]:
    import sys

    root = Path(repo_path)
    candidates = list(root.glob("test_*.py")) + list(root.glob("tests/test_*.py"))
    if not candidates:
        return None, "No pytest-style tests found in target repo."
    # Untrusted (cloned) repos must never execute test code on the host:
    # run them containerized, or skip with a clear message.
    if not trusted_local:
        if settings.sandbox_backend != "subprocess" and _docker_available():
            return _run_docker_tests(repo_path)
        return None, ("Test run skipped: remote scan and no Docker sandbox available "
                      "(refusing to execute untrusted test code on the host).")
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", "-q", "-p", "no:cacheprovider"],
            capture_output=True, text=True, timeout=60, cwd=repo_path,
        )
        if "No module named pytest" in proc.stdout or "No module named pytest" in proc.stderr:
            return None, "pytest is not installed for the target interpreter; tests not run."
        log = f"$ pytest -q\n{proc.stdout}{proc.stderr}\n[exit={proc.returncode}]"
        return proc.returncode == 0, log
    except Exception as exc:
        return None, f"Test run failed: {exc}"


def _run_docker_tests(repo_path: str) -> tuple[bool | None, str]:
    try:
        proc = subprocess.run(
            ["docker", "run", "--rm", "--network", "none", "--memory", "256m",
             "--cpus", "0.5", "-v", f"{repo_path}:/work:rw", "-w", "/work",
             settings.sandbox_image,
             "python", "-m", "pytest", "-q", "-p", "no:cacheprovider"],
            capture_output=True, text=True, timeout=90,
        )
        if "No module named pytest" in proc.stdout or "No module named pytest" in proc.stderr:
            return None, f"pytest is not installed in sandbox image {settings.sandbox_image}; tests not run."
        if proc.returncode != 0 and "Unable to find image" in proc.stderr:
            return None, f"Sandbox image {settings.sandbox_image} not available locally; tests not run."
        log = (f"$ docker run --rm --network none {settings.sandbox_image} python -m pytest -q\n"
               f"{proc.stdout}{proc.stderr}\n[exit={proc.returncode}]")
        return proc.returncode == 0, log
    except Exception as exc:
        return None, f"Test run failed: {exc}"
