//! GitHub helper endpoints: import + file view (ports
//! `backend/app/routers/github.py`).

use std::io::Read;
use std::path::Path as FsPath;

use axum::body::Bytes;
use axum::extract::{Query, State};
use axum::routing::{get, post};
use axum::{Json, Router};

use crate::routes::{parse_json, ApiError};
use crate::schemas::{FileQuery, ImportPayload};
use crate::state::AppState;

/// Upper bound on bytes pulled off disk for the file viewer (decoded and
/// truncated to 100k chars afterwards).
const MAX_FILE_BYTES: u64 = 110_000;

pub fn routes() -> Router<AppState> {
    Router::new()
        .route("/api/github/import", post(import_repo))
        .route("/api/github/file", get(read_file))
}

async fn import_repo(
    State(state): State<AppState>,
    body: Bytes,
) -> Result<Json<serde_json::Value>, ApiError> {
    let payload: ImportPayload = parse_json(&body)?;
    state
        .store
        .init_db()
        .map_err(|e| ApiError::internal(e.to_string()))?;
    let url = payload.repo_url.unwrap_or_default().trim().to_string();
    if url.is_empty() {
        return Err(ApiError::unprocessable("repo_url required"));
    }
    if url.len() > 2048 {
        return Err(ApiError::unprocessable("repo_url too long"));
    }
    let branch = payload
        .branch
        .unwrap_or_else(|| "HEAD".to_string())
        .trim()
        .to_string();
    let branch = if branch.is_empty() {
        "HEAD".to_string()
    } else {
        branch
    };
    if branch.len() > 256 {
        return Err(ApiError::unprocessable("branch too long"));
    }
    let scan = state
        .store
        .create_scan(&url, &branch)
        .map_err(|e| ApiError::internal(e.to_string()))?;
    // Queue the pipeline in the background and return immediately for
    // polling; awaiting it inline would hang the request for minutes.
    let store = state.store.clone();
    let settings = state.settings.clone();
    let scan_id = scan.id.clone();
    tokio::spawn(async move {
        patchproof_core::pipeline::run_pipeline(store, settings, scan_id).await;
    });
    Ok(Json(
        serde_json::json!({"scan_id": scan.id, "status": scan.status}),
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
    // Bounded read: a huge file in a scanned repo must not OOM the server.
    let file = std::fs::File::open(&canonical_target)
        .map_err(|_| ApiError::not_found("file not found"))?;
    let mut bytes = Vec::new();
    file.take(MAX_FILE_BYTES)
        .read_to_end(&mut bytes)
        .map_err(|_| ApiError::not_found("file not found"))?;
    let content = String::from_utf8_lossy(&bytes);
    let truncated: String = content.chars().take(100_000).collect();
    Ok(Json(serde_json::json!({
        "scan_id": query.scan_id,
        "path": query.path,
        "content": truncated,
    })))
}
