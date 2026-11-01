//! API routes (ports `backend/app/routers/`).

pub mod github;
pub mod health;
pub mod scans;

use axum::http::StatusCode;
use axum::response::{IntoResponse, Response};
use axum::Json;

/// JSON error body matching FastAPI's `{"detail": ...}` shape.
pub enum ApiError {
    NotFound(String),
    Unprocessable(String),
    Internal(String),
}

impl ApiError {
    pub fn not_found(msg: impl Into<String>) -> Self {
        Self::NotFound(msg.into())
    }

    pub fn unprocessable(msg: impl Into<String>) -> Self {
        Self::Unprocessable(msg.into())
    }

    pub fn internal(msg: impl Into<String>) -> Self {
        Self::Internal(msg.into())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, detail) = match self {
            Self::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
            Self::Unprocessable(msg) => (StatusCode::UNPROCESSABLE_ENTITY, msg),
            Self::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
        };
        (status, Json(serde_json::json!({"detail": detail}))).into_response()
    }
}
