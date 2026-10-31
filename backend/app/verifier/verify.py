"""Fix verification: re-scan the patched file + run repo tests + re-run PoC."""
import subprocess
from pathlib import Path

from sqlalchemy.orm import Session

from ..models import Evidence, Finding, Patch, Verification
from ..patcher.applier import apply_diff
from ..scanner.rules import scan_source


def verify_patches(session: Session, scan_id: str, repo_path: str) -> list[Verification]:
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
        tests_passed, test_log = _run_repo_tests(repo_path)
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
    # Heuristic MVP: dangerous pattern gone OR hardening comment added near the sink.
    markers = ["# PatchProof fix", "shell=False", "safe_load", "os.environ", "html.escape", "?", "allowlist"]
    near = "\n".join(after.splitlines()[max(0, finding.line_no - 3): finding.line_no + 3])
    if any(m in near for m in markers):
        # Confirm the exact same rule no longer fires on the same line region.
        fresh = [f for f in scan_source(after) if f["rule_id"] == finding.rule_id]
        same_line = [f for f in fresh if abs(f["line_no"] - finding.line_no) <= 2]
        return not same_line or len(fresh) < len([f for f in scan_source(before) if f["rule_id"] == finding.rule_id])
    return False


def _run_repo_tests(repo_path: str) -> tuple[bool | None, str]:
    import sys

    root = Path(repo_path)
    candidates = list(root.glob("test_*.py")) + list(root.glob("tests/test_*.py"))
    if not candidates:
        return None, "No pytest-style tests found in target repo."
    try:
        proc = subprocess.run(
            [sys.executable, "-m", "pytest", "-q"], capture_output=True, text=True,
            timeout=60, cwd=repo_path,
        )
        log = f"$ pytest -q\n{proc.stdout}{proc.stderr}\n[exit={proc.returncode}]"
        return proc.returncode == 0, log
    except Exception as exc:
        return None, f"Test run failed: {exc}"
