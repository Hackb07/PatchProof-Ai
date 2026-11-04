"""Patcher round-trip: deterministic fixes apply and rescan clean."""
import ast
import shutil
from types import SimpleNamespace

from app.patcher.applier import apply_diff
from app.patcher.generator import _deterministic_fix
from app.scanner.rules import scan_source


def _finding(rule_id, line_no):
    return SimpleNamespace(file_path="app.py", line_no=line_no, rule_id=rule_id)


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


def test_sequential_patches_same_checkout_all_land(tmp_path, fixture_repo):
    """Diffs generated against the original file must all apply to ONE
    checkout (the verifier's flow), each landing on its own sink."""
    repo = tmp_path / "repo"
    shutil.copytree(fixture_repo, repo)
    source = (repo / "app.py").read_text()
    raws = scan_source(source, "app.py")
    assert len(raws) >= 7

    diffs = []
    for raw in raws:
        finding = _finding(raw["rule_id"], raw["line_no"])
        diff, _summary = _deterministic_fix(str(repo), finding, "hint")
        assert diff, raw
        diffs.append(diff)
    for raw, diff in zip(raws, diffs):
        assert apply_diff(str(repo), diff), raw
    patched = (repo / "app.py").read_text()
    ast.parse(patched)
    assert scan_source(patched, "app.py") == []


def test_cmdi_multiword_command_becomes_argv(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text('import subprocess\nsubprocess.run(f"ls -la {d}", shell=True)\n')
    diff, _summary = _deterministic_fix(str(repo), _finding("PY-CMDI-001", 2), "hint")
    assert '["ls", "-la", d]' in diff, diff
    assert "shell=False" in diff, diff
    assert apply_diff(str(repo), diff)
    patched = (repo / "app.py").read_text()
    assert "PY-CMDI-001" not in {f["rule_id"] for f in scan_source(patched, "app.py")}


def test_cmdi_string_without_argv_gets_advisory_only(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text('import subprocess\nsubprocess.run("ls -la", shell=True)\n')
    diff, summary = _deterministic_fix(str(repo), _finding("PY-CMDI-001", 2), "hint")
    assert summary.startswith("Advisory"), (summary, diff)


def test_sqli_double_quoted_placeholder_and_comment_paren(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("cursor.execute(f'SELECT * FROM t WHERE a = \"{v}\"')  # foo()\n")
    diff, _summary = _deterministic_fix(str(repo), _finding("PY-SQLI-001", 1), "hint")
    assert "= ?', (v,))  # foo()" in diff, diff
    assert '"?"' not in diff, diff


def test_from_import_does_not_satisfy_need_import(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text('from html import escape\nrender_template_string("<h1>" + name + "</h1>")\n')
    diff, _summary = _deterministic_fix(str(repo), _finding("PY-XSS-001", 2), "hint")
    assert "+import html" in diff, diff


def test_pickle_load_fixed_like_loads(tmp_path):
    repo = tmp_path / "repo"
    repo.mkdir()
    (repo / "app.py").write_text("import pickle\ndata = pickle.load(f)\n")
    diff, _summary = _deterministic_fix(str(repo), _finding("PY-DESER-001", 2), "hint")
    assert "json.load(f)" in diff, diff
