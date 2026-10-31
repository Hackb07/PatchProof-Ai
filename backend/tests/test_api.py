"""End-to-end pipeline test on the local vulnerable fixture (mock LLM)."""
import time

import app.store as store


def test_health(client):
    resp = client.get("/api/health")
    assert resp.status_code == 200
    assert resp.json()["status"] == "ok"


def test_fixture_scan_end_to_end(client, fixture_repo, tmp_path, monkeypatch):
    monkeypatch.setenv("LLM_MOCK", "1")
    # Point repo clones at a temp dir to keep the test hermetic.
    import app.config as config
    import app.agents.planner as planner

    config.settings.repo_root = str(tmp_path / "repos")

    resp = client.post("/api/scans", json={"repo_url": fixture_repo})
    assert resp.status_code == 200, resp.text
    scan_id = resp.json()["id"]

    # Background pipeline runs inline in TestClient; poll briefly for completion.
    deadline = time.time() + 60
    status = ""
    while time.time() < deadline:
        detail = client.get(f"/api/scans/{scan_id}").json()
        status = detail["status"]
        if status in ("done", "failed"):
            break
        time.sleep(0.5)
    assert status == "done", detail

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

        verifs = session.query(Verification).join(Patch).join(Finding).filter(Finding.scan_id == scan_id).all()
        assert len(verifs) == len(patches)
        assert {v.status for v in verifs} <= {"fixed", "unfixed", "inconclusive"}
    finally:
        session.close()
