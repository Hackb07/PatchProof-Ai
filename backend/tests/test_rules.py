"""Positive + negative cases for every MVP rule."""
from app.scanner.rules import scan_source


def _ids(source: str) -> set[str]:
    return {f["rule_id"] for f in scan_source(source)}


def test_sqli_positive_and_negative():
    vuln = 'cursor.execute(f"SELECT * FROM users WHERE name = \'{name}\'")\n'
    assert "PY-SQLI-001" in _ids(vuln)
    safe = 'cursor.execute("SELECT * FROM users WHERE name = ?", (name,))\n'
    assert "PY-SQLI-001" not in _ids(safe)


def test_cmdi_positive_and_negative():
    vuln = 'import subprocess\nsubprocess.run(f"ls {d}", shell=True)\n'
    assert "PY-CMDI-001" in _ids(vuln)
    safe = 'import subprocess\nsubprocess.run(["ls", d], shell=False)\n'
    assert "PY-CMDI-001" not in _ids(safe)


def test_xss_positive_and_negative():
    vuln = 'from flask import render_template_string\nrender_template_string("<h1>" + name + "</h1>")\n'
    assert "PY-XSS-001" in _ids(vuln)
    safe = 'import html\nout = "<h1>" + html.escape(name) + "</h1>"\n'
    assert "PY-XSS-001" not in _ids(safe)


def test_pathtraversal_positive_and_negative():
    vuln = 'open(f"/srv/data/{filename}")\n'
    assert "PY-PATHTRAV-001" in _ids(vuln)
    safe = 'open("/srv/data/static.txt")\n'
    assert "PY-PATHTRAV-001" not in _ids(safe)


def test_deser_positive_and_negative():
    vuln = 'import pickle\npickle.loads(data)\n'
    assert "PY-DESER-001" in _ids(vuln)
    safe = 'import json\njson.loads(data)\n'
    assert "PY-DESER-001" not in _ids(safe)


def test_secret_positive_and_negative():
    vuln = 'API_KEY = "sk-live-abcdef123456"\n'
    assert "PY-SECRET-001" in _ids(vuln)
    safe = 'import os\nAPI_KEY = os.environ["API_KEY"]\n'
    assert "PY-SECRET-001" not in _ids(safe)


def test_ssrf_positive_and_negative():
    vuln = 'import requests\nrequests.get(f"https://api.example.com/{path}")\n'
    assert "PY-SSRF-001" in _ids(vuln)
    safe = 'ALLOWED = {"api.example.com"}\n'
    assert "PY-SSRF-001" not in _ids(safe)


def test_patched_shapes_rescan_clean():
    """Every shape the deterministic fixer emits must not re-trigger its rule."""
    cases = {
        "PY-SQLI-001": 'cursor.execute("SELECT * FROM users WHERE name = ?", (name,))\n',
        "PY-CMDI-001": 'import subprocess\nsubprocess.run(["ls", d], shell=False)\n',
        "PY-XSS-001": 'import html\nrender_template_string("<h1>" + html.escape(name) + "</h1>")\n',
        "PY-PATHTRAV-001": 'open(_confined_path("/srv/data", filename))\n',
        "PY-DESER-001": 'import json\njson.loads(data)\n',
        "PY-SECRET-001": 'import os\nAPI_KEY = os.environ["API_KEY"]\n',
        "PY-SSRF-001": 'import requests\nrequests.get(_checked_url(url), timeout=5)\n',
    }
    for rule_id, source in cases.items():
        assert rule_id not in _ids(source), rule_id
