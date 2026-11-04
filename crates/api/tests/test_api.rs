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
    let path: PathBuf = Path::new(env!("CARGO_MANIFEST_DIR")).join("../../fixtures/vuln-app");
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
    get_json_headers(app, uri, &[]).await
}

async fn get_json_headers(
    app: axum::Router,
    uri: &str,
    headers: &[(&str, &str)],
) -> (StatusCode, serde_json::Value) {
    let mut builder = Request::builder().uri(uri).method("GET");
    for (k, v) in headers {
        builder = builder.header(*k, *v);
    }
    let req = builder.body(Body::empty()).unwrap();
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
    post_raw(app, uri, &body.to_string()).await
}

async fn post_raw(app: axum::Router, uri: &str, raw: &str) -> (StatusCode, serde_json::Value) {
    let req = Request::builder()
        .uri(uri)
        .method("POST")
        .header("content-type", "application/json")
        .body(Body::from(raw.to_string()))
        .unwrap();
    let resp = app.oneshot(req).await.unwrap();
    let status = resp.status();
    let bytes = axum::body::to_bytes(resp.into_body(), 32 * 1024 * 1024)
        .await
        .unwrap();
    let json: serde_json::Value = serde_json::from_slice(&bytes).unwrap();
    (status, json)
}

async fn delete_json(app: axum::Router, uri: &str) -> (StatusCode, serde_json::Value) {
    let req = Request::builder()
        .uri(uri)
        .method("DELETE")
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

async fn wait_for_done(state: &AppState, scan_id: &str) -> serde_json::Value {
    let deadline = tokio::time::Instant::now() + Duration::from_secs(120);
    loop {
        let (_s, current) =
            get_json(build_app(state.clone()), &format!("/api/scans/{scan_id}")).await;
        let status = current["status"].as_str().unwrap_or("").to_string();
        if status == "done" || status == "failed" {
            return current;
        }
        assert!(
            tokio::time::Instant::now() < deadline,
            "timed out waiting for scan: {current}"
        );
        tokio::time::sleep(Duration::from_millis(200)).await;
    }
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
    let detail = wait_for_done(&state, &scan_id).await;
    assert_eq!(detail["status"], "done", "{detail}");

    let findings = state.store.list_findings(&scan_id).unwrap();
    let rule_ids: HashSet<String> = findings.iter().map(|f| f.rule_id.clone()).collect();
    for expected in [
        "PY-SQLI-001",
        "PY-CMDI-001",
        "PY-DESER-001",
        "PY-SECRET-001",
    ] {
        assert!(rule_ids.contains(expected), "rules: {rule_ids:?}");
    }
    assert!(findings.iter().all(|f| f.risk_score > 0.0));
    assert!(findings.iter().all(|f| !f.repro_log.is_empty()));

    let patches = state.store.scan_patches(&scan_id).unwrap();
    assert_eq!(patches.len(), findings.len());
    assert!(patches.iter().all(|p| !p.diff.is_empty()));
    // Every patch must land on its own sink (content-matched application).
    assert!(patches.iter().all(|p| p.applied));

    let verifs = state.store.scan_verifications(&scan_id).unwrap();
    assert_eq!(verifs.len(), patches.len());
    // Every deterministic fix must verify: the rescan is anchored on the
    // fix comment, so helper insertions can't shift it out of the window.
    for v in &verifs {
        assert_eq!(v.status, "fixed", "patch {}: {}", v.patch_id, v.notes);
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

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_create_scan_validation() {
    let tmp = tempfile::tempdir().unwrap();
    let state = test_state(tmp.path());

    // Missing repo_url.
    let (status, body) = post_json(
        build_app(state.clone()),
        "/api/scans",
        serde_json::json!({}),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert!(body.get("detail").is_some(), "{body}");

    // Empty repo_url (same rule as the import endpoint).
    let (status, _) = post_json(
        build_app(state.clone()),
        "/api/scans",
        serde_json::json!({"repo_url": "   "}),
    )
    .await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY);

    // Malformed JSON still yields the {"detail": ...} shape.
    let (status, body) = post_raw(build_app(state.clone()), "/api/scans", "{\"repo_url\":").await;
    assert_eq!(status, StatusCode::UNPROCESSABLE_ENTITY, "{body}");
    assert!(body.get("detail").is_some(), "{body}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_list_returns_summaries() {
    let tmp = tempfile::tempdir().unwrap();
    let state = test_state(tmp.path());

    let (status, _) = post_json(
        build_app(state.clone()),
        "/api/scans",
        serde_json::json!({"repo_url": fixture_repo()}),
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    let (status, body) = get_json(build_app(state.clone()), "/api/scans").await;
    assert_eq!(status, StatusCode::OK);
    let rows = body.as_array().unwrap();
    assert_eq!(rows.len(), 1);
    assert!(rows[0].get("finding_count").is_some(), "{body}");
    assert!(rows[0].get("evidence_count").is_some(), "{body}");
    assert!(rows[0].get("findings").is_none(), "{body}");
}

#[tokio::test(flavor = "multi_thread", worker_threads = 4)]
async fn test_rerun_starts_clean() {
    let tmp = tempfile::tempdir().unwrap();
    let state = test_state(tmp.path());

    let (_, body) = post_json(
        build_app(state.clone()),
        "/api/scans",
        serde_json::json!({"repo_url": fixture_repo()}),
    )
    .await;
    let scan_id = body["id"].as_str().unwrap().to_string();
    let first = wait_for_done(&state, &scan_id).await;
    assert_eq!(first["status"], "done", "{first}");
    let first_count = first["findings"].as_array().unwrap().len();
    assert!(first_count >= 7);

    let (status, _) = post_raw(
        build_app(state.clone()),
        &format!("/api/scans/{scan_id}/rerun"),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::OK);
    let second = wait_for_done(&state, &scan_id).await;
    assert_eq!(second["status"], "done", "{second}");
    // No duplication: the rerun cleared the previous results first.
    assert_eq!(second["findings"].as_array().unwrap().len(), first_count);
    let patches = state.store.scan_patches(&scan_id).unwrap();
    assert_eq!(patches.len(), first_count);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_import_queues_in_background() {
    let tmp = tempfile::tempdir().unwrap();
    let state = test_state(tmp.path());

    let (status, body) = post_json(
        build_app(state.clone()),
        "/api/github/import",
        serde_json::json!({"repo_url": fixture_repo()}),
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    // Returns immediately for polling instead of running inline.
    assert_eq!(body["status"], "queued");
    assert!(body["scan_id"].as_str().is_some_and(|s| s.len() == 12));
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_api_key_auth() {
    let tmp = tempfile::tempdir().unwrap();
    let mut state = test_state(tmp.path());
    state.settings.api_key = "secret".to_string();

    let (status, _) = get_json(build_app(state.clone()), "/api/scans").await;
    assert_eq!(status, StatusCode::UNAUTHORIZED);

    let (status, _) = get_json_headers(
        build_app(state.clone()),
        "/api/scans",
        &[("x-api-key", "secret")],
    )
    .await;
    assert_eq!(status, StatusCode::OK);

    // Health stays open.
    let (status, _) = get_json(build_app(state.clone()), "/api/health").await;
    assert_eq!(status, StatusCode::OK);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_list_pagination() {
    let tmp = tempfile::tempdir().unwrap();
    let state = test_state(tmp.path());
    for i in 0..3 {
        state
            .store
            .create_scan(&format!("/tmp/repo-{i}"), "HEAD")
            .unwrap();
    }
    let (status, body) = get_json(build_app(state.clone()), "/api/scans?limit=2").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_array().unwrap().len(), 2);

    let (status, body) = get_json(build_app(state.clone()), "/api/scans?limit=2&offset=2").await;
    assert_eq!(status, StatusCode::OK);
    assert_eq!(body.as_array().unwrap().len(), 1);

    let (status, body) = get_json(build_app(state.clone()), "/api/scans?limit=2&offset=10").await;
    assert_eq!(status, StatusCode::OK);
    assert!(body.as_array().unwrap().is_empty());
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_delete_scan() {
    let tmp = tempfile::tempdir().unwrap();
    let state = test_state(tmp.path());
    let scan = state.store.create_scan("/tmp/repo", "HEAD").unwrap();

    let (status, body) =
        delete_json(build_app(state.clone()), &format!("/api/scans/{}", scan.id)).await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["deleted"], true);

    let (status, _) = get_json(build_app(state.clone()), &format!("/api/scans/{}", scan.id)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);

    let (status, _) =
        delete_json(build_app(state.clone()), &format!("/api/scans/{}", scan.id)).await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}

#[tokio::test(flavor = "multi_thread", worker_threads = 2)]
async fn test_cancel_scan() {
    let tmp = tempfile::tempdir().unwrap();
    let state = test_state(tmp.path());
    // Create directly in the store so no background pipeline races the cancel.
    let scan = state.store.create_scan("/tmp/repo", "HEAD").unwrap();

    let (status, body) = post_raw(
        build_app(state.clone()),
        &format!("/api/scans/{}/cancel", scan.id),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::OK, "{body}");
    assert_eq!(body["status"], "cancelled");

    // Cancelling a terminal scan is a conflict.
    let (status, body) = post_raw(
        build_app(state.clone()),
        &format!("/api/scans/{}/cancel", scan.id),
        "",
    )
    .await;
    assert_eq!(status, StatusCode::CONFLICT, "{body}");
    assert!(body.get("detail").is_some());

    let (status, _) = post_raw(
        build_app(state.clone()),
        "/api/scans/doesnotexist/cancel",
        "",
    )
    .await;
    assert_eq!(status, StatusCode::NOT_FOUND);
}
