//! Scan endpoints: submit repo, poll status, fetch full report (ports
//! `backend/app/routers/scans.py`).

use axum::extract::{Path, State};
use axum::routing::{get, post};
use axum::{Json, Router};

use crate::routes::ApiError;
use crate::schemas::{serialize_scan, ScanCreate, ScanOut};
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/scans", post(create_scan).get(list_scans))
        .route("/api/scans/{id}", get(get_scan))
        .route("/api/scans/{id}/rerun", post(rerun_scan))
}

async fn create_scan(
    State(state): State<AppState>,
    Json(payload): Json<ScanCreate>,
) -> Result<Json<ScanOut>, ApiError> {
    state
        .store
        .init_db()
        .map_err(|e| ApiError::internal(e.to_string()))?;
    let branch = payload.branch.unwrap_or_default();
    let branch = if branch.is_empty() { "HEAD" } else { branch.as_str() };
    let scan = state
        .store
        .create_scan(&payload.repo_url, branch)
        .map_err(|e| ApiError::internal(e.to_string()))?;
    spawn_pipeline(&state, scan.id.clone());
    serialize_scan(&state.store, &scan.id)
        .map(Json)
        .ok_or_else(|| ApiError::internal("scan vanished after create"))
}

async fn list_scans(State(state): State<AppState>) -> Result<Json<Vec<ScanOut>>, ApiError> {
    state
        .store
        .init_db()
        .map_err(|e| ApiError::internal(e.to_string()))?;
    let scans = state
        .store
        .list_scans(50)
        .map_err(|e| ApiError::internal(e.to_string()))?;
    let mut out = Vec::with_capacity(scans.len());
    for s in &scans {
        if let Some(detail) = serialize_scan(&state.store, &s.id) {
            out.push(detail);
        }
    }
    Ok(Json(out))
}

async fn get_scan(
    State(state): State<AppState>,
    Path(scan_id): Path<String>,
) -> Result<Json<ScanOut>, ApiError> {
    serialize_scan(&state.store, &scan_id)
        .map(Json)
        .ok_or_else(|| ApiError::not_found("scan not found"))
}

async fn rerun_scan(
    State(state): State<AppState>,
    Path(scan_id): Path<String>,
) -> Result<Json<ScanOut>, ApiError> {
    let exists = state
        .store
        .get_scan(&scan_id)
        .map_err(|e| ApiError::internal(e.to_string()))?;
    if exists.is_none() {
        return Err(ApiError::not_found("scan not found"));
    }
    state
        .store
        .reset_scan_queued(&scan_id)
        .map_err(|e| ApiError::internal(e.to_string()))?;
    spawn_pipeline(&state, scan_id.clone());
    serialize_scan(&state.store, &scan_id)
        .map(Json)
        .ok_or_else(|| ApiError::not_found("scan not found"))
}

fn spawn_pipeline(state: &AppState, scan_id: String) {
    let store = state.store.clone();
    let settings = state.settings.clone();
    tokio::spawn(async move {
        patchproof_core::pipeline::run_pipeline(store, settings, scan_id).await;
    });
}
