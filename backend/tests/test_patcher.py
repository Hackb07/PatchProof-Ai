"""Patcher round-trip: deterministic fixes apply and rescan clean."""
import ast
import shutil
from types import SimpleNamespace

from app.patcher.applier import apply_diff
from app.patcher.generator import _deterministic_fix
from app.scanner.rules import scan_source


def test_fixture_patches_apply_and_rescan_clean(tmp_path, fixture_repo):
    repo = tmp_path / "repo"
    shutil.copytree(fixture_repo, repo)
    source = (repo / "app.py").read_text()
    raws = scan_source(source, "app.py")
    assert len(raws) >= 7

    # Apply one finding at a time on fresh copies (line numbers stay valid).
    for raw in raws:
        trial = tmp_path / f"trial-{raw['rule_id']}-{raw['line_no']}"
        shutil.copytree(fixture_repo, trial)
        finding = SimpleNamespace(file_path="app.py", line_no=raw["line_no"], rule_id=raw["rule_id"])
        diff, _summary = _deterministic_fix(str(trial), finding, "hint")
        assert diff, raw
        assert apply_diff(str(trial), diff), raw
        patched = (trial / "app.py").read_text()
        ast.parse(patched)  # must stay syntactically valid
        fresh = [f for f in scan_source(patched, "app.py") if f["rule_id"] == raw["rule_id"]]
        near = [f for f in fresh if abs(f["line_no"] - raw["line_no"]) <= 4]
        assert not near, (raw, [f["line_no"] for f in fresh])
