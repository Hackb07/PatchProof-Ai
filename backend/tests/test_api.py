"""End-to-end pipeline test on the local vulnerable fixture (mock LLM)."""
import time

import app.store as store


def _wait_done(client, scan_id, timeout=60):
    deadline = time.time() + timeout
    detail = {}
    while time.time() < deadline:
        detail = client.get(f"/api/scans/{scan_id}").json()
        if detail["status"] in ("done", "failed"):
            return detail
        time.sleep(0.5)
    return detail


def test_health(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_fixture_scan_end_to_end(client, fixture_repo, tmp_path, monkeypatch):
    monkeypatch.setenv("LLM_MOCK", "1")
    # Point repo clones at a temp dir to keep the test hermetic.
    import app.config as config

    config.settings.repo_root = str(tmp_path / "repos")

    resp = client.post("/api/scans", json={"repo_url": fixture_repo})
    assert resp.status_code == 200, resp.text
    scan_id = resp.json()["id"]

    # Background pipeline runs inline in TestClient; poll briefly for completion.
    detail = _wait_done(client, scan_id)
    assert detail["status"] == "done", detail

    session = store.SessionLocal()
    try:
        from app.models import Finding, Patch, Verification

        findings = session.query(Finding).filter_by(scan_id=scan_id).all()
        rule_ids = {f.rule_id for f in findings}
        assert "PY-SQLI-001" in rule_ids
        assert "PY-CMDI-001" in rule_ids
        assert "PY-DESER-001" in rule_ids
        assert "PY-SECRET-001" in rule_ids
        assert all(f.risk_score > 0 for f in findings)
        assert all(f.repro_log for f in findings)

        patches = session.query(Patch).join(Finding).filter(Finding.scan_id == scan_id).all()
        assert len(patches) == len(findings)
        assert all(p.diff for p in patches)
        assert all(p.applied for p in patches)

        verifs = session.query(Verification).join(Patch).join(Finding).filter(Finding.scan_id == scan_id).all()
        assert len(verifs) == len(patches)
        assert {v.status for v in verifs} == {"fixed"}
    finally:
        session.close()


def test_create_scan_validation(client):
    assert client.post("/api/scans", json={}).status_code == 422
    assert client.post("/api/scans", json={"repo_url": "   "}).status_code == 422


def test_list_returns_summaries(client, fixture_repo, tmp_path):
    import app.config as config

    config.settings.repo_root = str(tmp_path / "repos")
    resp = client.post("/api/scans", json={"repo_url": fixture_repo})
    assert resp.status_code == 200, resp.text
    rows = client.get("/api/scans").json()
    assert len(rows) == 1
    assert "finding_count" in rows[0]
    assert "evidence_count" in rows[0]
    assert "findings" not in rows[0]


def test_rerun_starts_clean(client, fixture_repo, tmp_path):
    import app.config as config

    config.settings.repo_root = str(tmp_path / "repos")
    scan_id = client.post("/api/scans", json={"repo_url": fixture_repo}).json()["id"]
    first = _wait_done(client, scan_id)
    assert first["status"] == "done", first
    first_count = len(first["findings"])
    assert first_count >= 7

    resp = client.post(f"/api/scans/{scan_id}/rerun")
    assert resp.status_code == 200, resp.text
    second = _wait_done(client, scan_id)
    assert second["status"] == "done", second
    assert len(second["findings"]) == first_count


def test_scan_not_found_and_bad_import(client):
    assert client.get("/api/scans/doesnotexist").status_code == 404
    assert client.post("/api/github/import", json={"repo_url": ""}).status_code == 422
