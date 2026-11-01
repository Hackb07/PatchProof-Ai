//! PatchProof AI HTTP API (axum port of `backend/app/main.py`).

pub mod routes;
pub mod schemas;
pub mod state;

pub use state::AppState;

use axum::Router;
use tower_http::cors::{AllowOrigin, Any, CorsLayer};

/// Build the full application router with shared state and CORS.
pub fn build_app(state: AppState) -> Router {
    Router::new()
        .merge(routes::health::routes())
        .merge(routes::scans::routes())
        .merge(routes::github::routes())
        .with_state(state.clone())
        .layer(cors_layer(&state.settings))
}

fn cors_layer(settings: &patchproof_core::config::Settings) -> CorsLayer {
    let origins = settings.cors_list();
    let allow_origin = if origins.iter().any(|o| o == "*") {
        AllowOrigin::any()
    } else {
        let values: Vec<axum::http::HeaderValue> = origins
            .iter()
            .filter_map(|o| o.parse().ok())
            .collect();
        if values.is_empty() {
            AllowOrigin::any()
        } else {
            AllowOrigin::list(values)
        }
    };
    CorsLayer::new()
        .allow_origin(allow_origin)
        .allow_credentials(true)
        .allow_methods(Any)
        .allow_headers(Any)
}
