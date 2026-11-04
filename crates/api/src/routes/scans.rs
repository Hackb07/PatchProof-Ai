//! Scan endpoints: submit repo, poll status, fetch full report (ports
//! `backend/app/routers/scans.py`).

use axum::body::Bytes;
use axum::extract::{Path, Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};

use crate::routes::{parse_json, ApiError};
use crate::schemas::{
    serialize_scan, serialize_summary, ScanCreate, ScanListQuery, ScanOut, ScanSummary,
};
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/scans", post(create_scan).get(list_scans))
        .route("/api/scans/:id", get(get_scan).delete(delete_scan))
        .route("/api/scans/:id/rerun", post(rerun_scan))
        .route("/api/scans/:id/cancel", post(cancel_scan))
}

async fn create_scan(
    State(state): State<AppState>,
    body: Bytes,
) -> Result<Json<ScanOut>, ApiError> {
    let payload: ScanCreate = parse_json(&body)?;
    state
        .store
        .init_db()
        .map_err(|e| ApiError::internal(e.to_string()))?;
    let repo_url = payload.repo_url.trim().to_string();
    if repo_url.is_empty() {
        return Err(ApiError::unprocessable("repo_url required"));
    }
    if repo_url.len() > 2048 {
        return Err(ApiError::unprocessable("repo_url too long"));
    }
    let branch = payload.branch.unwrap_or_default();
    let branch = branch.trim();
    let branch = if branch.is_empty() { "HEAD" } else { branch };
    if branch.len() > 256 {
        return Err(ApiError::unprocessable("branch too long"));
    }
    let scan = state
        .store
        .create_scan(&repo_url, branch)
        .map_err(|e| ApiError::internal(e.to_string()))?;
    spawn_pipeline(&state, scan.id.clone());
    serialize_scan(&state.store, &scan.id).map(Json)
}

async fn list_scans(
    State(state): State<AppState>,
    Query(query): Query<ScanListQuery>,
) -> Result<Json<Vec<ScanSummary>>, ApiError> {
    state
        .store
        .init_db()
        .map_err(|e| ApiError::internal(e.to_string()))?;
    let limit = query.limit.unwrap_or(50).clamp(1, 200);
    let offset = query.offset.unwrap_or(0).max(0);
    let scans = state
        .store
        .list_scans_paginated(limit, offset)
        .map_err(|e| ApiError::internal(e.to_string()))?;
    let mut out = Vec::with_capacity(scans.len());
    for s in &scans {
        out.push(serialize_summary(&state.store, s)?);
    }
    Ok(Json(out))
}

async fn get_scan(
    State(state): State<AppState>,
    Path(scan_id): Path<String>,
) -> Result<Json<ScanOut>, ApiError> {
    serialize_scan(&state.store, &scan_id).map(Json)
}

async fn delete_scan(
    State(state): State<AppState>,
    Path(scan_id): Path<String>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let scan = state
        .store
        .get_scan(&scan_id)
        .map_err(|e| ApiError::internal(e.to_string()))?
        .ok_or_else(|| ApiError::not_found("scan not found"))?;
    state
        .store
        .delete_scan(&scan_id)
        .map_err(|e| ApiError::internal(e.to_string()))?;
    // Best-effort checkout cleanup; the DB rows are already gone.
    if !scan.repo_path.is_empty() {
        let _ = std::fs::remove_dir_all(&scan.repo_path);
    } else {
        let fallback = std::path::Path::new(&state.settings.repo_root).join(&scan_id);
        let _ = std::fs::remove_dir_all(fallback);
    }
    Ok(Json(serde_json::json!({"deleted": true, "id": scan_id})))
}

async fn cancel_scan(
    State(state): State<AppState>,
    Path(scan_id): Path<String>,
) -> Result<Json<ScanOut>, ApiError> {
    let scan = state
        .store
        .get_scan(&scan_id)
        .map_err(|e| ApiError::internal(e.to_string()))?
        .ok_or_else(|| ApiError::not_found("scan not found"))?;
    if ["done", "failed", "cancelled"].contains(&scan.status.as_str()) {
        return Err(ApiError::conflict(format!("scan already {}", scan.status)));
    }
    state
        .store
        .cancel_scan(&scan_id)
        .map_err(|e| ApiError::internal(e.to_string()))?;
    state
        .store
        .add_evidence(&scan_id, "done", "planner", "Scan cancelled by user", "")
        .map_err(|e| ApiError::internal(e.to_string()))?;
    serialize_scan(&state.store, &scan_id).map(Json)
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
    // Drop the previous run's results so the new pipeline starts clean;
    // otherwise triage dedupes the new findings against the stale ones.
    state
        .store
        .clear_scan_results(&scan_id)
        .map_err(|e| ApiError::internal(e.to_string()))?;
    state
        .store
        .reset_scan_queued(&scan_id)
        .map_err(|e| ApiError::internal(e.to_string()))?;
    state
        .store
        .add_evidence(
            &scan_id,
            "done",
            "planner",
            "Scan re-queued for a fresh run",
            "",
        )
        .map_err(|e| ApiError::internal(e.to_string()))?;
    spawn_pipeline(&state, scan_id.clone());
    serialize_scan(&state.store, &scan_id).map(Json)
}

fn spawn_pipeline(state: &AppState, scan_id: String) {
    let store = state.store.clone();
    let settings = state.settings.clone();
    tokio::spawn(async move {
        patchproof_core::pipeline::run_pipeline(store, settings, scan_id).await;
    });
}
