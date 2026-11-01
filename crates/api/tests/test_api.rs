//! End-to-end pipeline test on the local vulnerable fixture with the
//! mock LLM (ports `backend/tests/test_api.py`).

use std::collections::HashSet;
use std::path::{Path, PathBuf};
use std::time::Duration;

use axum::body::Body;
use axum::http::{Request, StatusCode};
use patchproof_api::{build_app, AppState};
use patchproof_core::config::Settings;
use patchproof_core::store::Store;
use tower::ServiceExt;

fn fixture_repo() -> String {
    let path: PathBuf =
        Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/vuln-app");
    path.to_string_lossy().to_string()
}

fn test_state(tmp: &Path) -> AppState {
    let db = tmp.join("test.db");
    let settings = Settings {
        database_url: format!("sqlite://{}", db.to_string_lossy()),
        repo_root: tmp.join("repos").to_string_lossy().to_string(),
        llm_mock: true,
        ..Settings::default()
    };
    let store = Store::from_settings(&settings);
    store.init_db().unwrap();
    AppState { store, settings }
}

async fn get_json(app: axum::Router, uri: &str) -> (StatusCode, serde_json::Value) {
    let req = Request::builder()
        .uri(uri)
        .method("GET")
        .body(Body::empty())
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 32 * 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    (status, json)
}

async fn post_json(
    app: axum::Router,
    uri: &str,
    body: serde_json::Value,
) -> (StatusCode, serde_json::Value) {
    let req = Request::builder()
        .uri(uri)
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(body.to_string()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 32 * 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    (status, json)
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_health() {
    let tmp = tempfile::tempdir().unwrap();
    let state = test_state(tmp.path());
    let (status, body) = get_json(build_app(state), "/api/health").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body["status"], "ok");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_fixture_scan_end_to_end() {
    let tmp = tempfile::tempdir().unwrap();
    let state = test_state(tmp.path());

    let (status, body) = post_json(
        build_app(state.clone()),
        "/api/scans",
        serde_json::json!({"repo_url": fixture_repo()}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    let scan_id = body["id"].as_str().unwrap().to_string();

    // Background pipeline runs on the test runtime; poll for completion.
    let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
    let detail: serde_json::Value;
    loop {
        let (_s, current) = get_json(
            build_app(state.clone()),
            &format!("/api/scans/{scan_id}"),
        )
        .await;
        let status = current["status"].as_str().unwrap_or("").to_string();
        if status == "done" || status == "failed" {
            detail = current;
            break;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for scan: {current}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
    assert_eq!(detail["status"], "done", "{detail}");

    let findings = state.store.list_findings(&scan_id).unwrap();
    let rule_ids: HashSet<String> = findings.iter().map(|f| f.rule_id.clone()).collect();
    for expected in ["PY-SQLI-001", "PY-CMDI-001", "PY-DESER-001", "PY-SECRET-001"] {
        assert!(rule_ids.contains(expected), "rules: {rule_ids:?}");
    }
    assert!(findings.iter().all(|f| f.risk_score > 0.0));
    assert!(findings.iter().all(|f| !f.repro_log.is_empty()));

    let patches = state.store.scan_patches(&scan_id).unwrap();
    assert_eq!(patches.len(), findings.len());
    assert!(patches.iter().all(|p| !p.diff.is_empty()));

    let verifs = state.store.scan_verifications(&scan_id).unwrap();
    assert_eq!(verifs.len(), patches.len());
    for v in &verifs {
        assert!(
            ["fixed", "unfixed", "inconclusive"].contains(&v.status.as_str()),
            "status: {}",
            v.status
        );
    }
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_scan_not_found_and_bad_import() {
    let tmp = tempfile::tempdir().unwrap();
    let state = test_state(tmp.path());

    let (status, _) = get_json(build_app(state.clone()), "/api/scans/doesnotexist").await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, _) = post_json(
        build_app(state.clone()),
        "/api/github/import",
        serde_json::json!({"repo_url": ""}),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);
}
