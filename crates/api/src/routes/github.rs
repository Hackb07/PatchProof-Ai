//! GitHub helper endpoints: import + file view (ports
//! `backend/app/routers/github.py`).

use std::path::Path as FsPath;

use axum::extract::{Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};

use crate::routes::ApiError;
use crate::schemas::{FileQuery, ImportPayload};
use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/github/import", post(import_repo))
        .route("/api/github/file", get(read_file))
}

async fn import_repo(
    State(state): State<AppState>,
    Json(payload): Json<ImportPayload>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let url = payload.repo_url.unwrap_or_default().trim().to_string();
    if url.is_empty() {
        return Err(ApiError::unprocessable("repo_url required"));
    }
    let branch = payload.branch.unwrap_or_else(|| "HEAD".to_string());
    let scan = state
        .store
        .create_scan(&url, &branch)
        .map_err(|e| ApiError::internal(e.to_string()))?;
    // Run inline (clone happens in the pipeline); return the id for polling.
    patchproof_core::pipeline::run_pipeline(
        state.store.clone(),
        state.settings.clone(),
        scan.id.clone(),
    )
    .await;
    let updated = state
        .store
        .get_scan(&scan.id)
        .map_err(|e| ApiError::internal(e.to_string()))?
        .ok_or_else(|| ApiError::internal("scan vanished during import"))?;
    Ok(Json(
        serde_json::json!({"scan_id": updated.id, "status": updated.status}),
    ))
}

async fn read_file(
    State(state): State<AppState>,
    Query(query): Query<FileQuery>,
) -> Result<Json<serde_json::Value>, ApiError> {
    let scan = state
        .store
        .get_scan(&query.scan_id)
        .map_err(|e| ApiError::internal(e.to_string()))?
        .filter(|s| !s.repo_path.is_empty())
        .ok_or_else(|| ApiError::not_found("scan or repo not found"))?;
    let root = FsPath::new(&scan.repo_path);
    let canonical_root = root
        .canonicalize()
        .map_err(|_| ApiError::not_found("file not found"))?;
    let target = root.join(&query.path);
    let canonical_target = target
        .canonicalize()
        .map_err(|_| ApiError::not_found("file not found"))?;
    if !canonical_target.starts_with(&canonical_root) || !canonical_target.is_file() {
        return Err(ApiError::not_found("file not found"));
    }
    let bytes = std::fs::read(&canonical_target)
        .map_err(|_| ApiError::not_found("file not found"))?;
    let content = String::from_utf8_lossy(&bytes);
    let truncated: String = content.chars().take(100_000).collect();
    Ok(Json(serde_json::json!({
        "scan_id": query.scan_id,
        "path": query.path,
        "content": truncated,
    })))
}
