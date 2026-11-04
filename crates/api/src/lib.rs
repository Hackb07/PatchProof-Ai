//! PatchProof AI HTTP API (axum port of `backend/app/main.py`).

pub mod routes;
pub mod schemas;
pub mod state;

pub use state::AppState;

use axum::extract::State;
use axum::http::{header, Method, Request};
use axum::middleware::Next;
use axum::response::Response;
use axum::Router;
use tower_http::cors::{AllowOrigin, Any, CorsLayer};

use routes::ApiError;

/// Build the full application router with shared state and CORS.
pub fn build_app(state: AppState) -> Router {
    let authed = Router::new()
        .merge(routes::scans::routes())
        .merge(routes::github::routes())
        .route_layer(axum::middleware::from_fn_with_state(
            state.clone(),
            require_api_key,
        ));
    Router::new()
        .merge(routes::health::routes())
        .merge(authed)
        .with_state(state.clone())
        .layer(cors_layer(&state.settings))
}

/// Shared-secret auth for the scan endpoints (health stays open).
/// Open to all requests unless `PATCHPROOF_API_KEY` is configured.
async fn require_api_key(
    State(state): State<AppState>,
    req: Request<axum::body::Body>,
    next: Next,
) -> Result<Response, ApiError> {
    let expected = state.settings.api_key.trim();
    if expected.is_empty() {
        return Ok(next.run(req).await);
    }
    let headers = req.headers();
    let by_header = headers
        .get("x-api-key")
        .is_some_and(|v| v.as_bytes() == expected.as_bytes());
    let by_bearer = headers
        .get(header::AUTHORIZATION)
        .and_then(|v| v.to_str().ok())
        .is_some_and(|s| {
            s.strip_prefix("Bearer ")
                .is_some_and(|token| token.trim() == expected)
        });
    if by_header || by_bearer {
        Ok(next.run(req).await)
    } else {
        Err(ApiError::unauthorized("invalid or missing API key"))
    }
}

fn cors_layer(settings: &patchproof_core::config::Settings) -> CorsLayer {
    let origins = settings.cors_list();
    if origins.iter().any(|o| o == "*") {
        // Wildcard origin cannot be combined with credentials.
        return CorsLayer::new()
            .allow_origin(Any)
            .allow_methods(Any)
            .allow_headers(Any);
    }
    let explicit: Vec<axum::http::HeaderValue> =
        origins.iter().filter_map(|o| o.parse().ok()).collect();
    if explicit.is_empty() {
        // No origins configured: emit no CORS headers (deny by default).
        return CorsLayer::new();
    }
    CorsLayer::new()
        .allow_origin(AllowOrigin::list(explicit))
        .allow_credentials(true)
        .allow_methods([
            Method::GET,
            Method::POST,
            Method::PUT,
            Method::PATCH,
            Method::DELETE,
            Method::OPTIONS,
        ])
        .allow_headers([header::CONTENT_TYPE, header::AUTHORIZATION])
}
