//! Health endpoint.

use axum::extract::State;
use axum::routing::get;
use axum::{Json, Router};

use crate::state::AppState;

pub fn routes() -> Router<AppState> {
    Router::new().route("/api/health", get(health))
}

async fn health(State(state): State<AppState>) -> Json<serde_json::Value> {
    // Effective mock mode: forced on when no API key is configured.
    let mock = state.settings.llm_mock || state.settings.meta_api_key.is_empty();
    Json(serde_json::json!({
        "status": "ok",
        "app": state.settings.app_name,
        "llm_mock": mock,
    }))
}
