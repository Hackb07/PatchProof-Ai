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
    Unauthorized(String),
    Conflict(String),
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

    pub fn unauthorized(msg: impl Into<String>) -> Self {
        Self::Unauthorized(msg.into())
    }

    pub fn conflict(msg: impl Into<String>) -> Self {
        Self::Conflict(msg.into())
    }
}

impl IntoResponse for ApiError {
    fn into_response(self) -> Response {
        let (status, detail) = match self {
            Self::NotFound(msg) => (StatusCode::NOT_FOUND, msg),
            Self::Unprocessable(msg) => (StatusCode::UNPROCESSABLE_ENTITY, msg),
            Self::Internal(msg) => (StatusCode::INTERNAL_SERVER_ERROR, msg),
            Self::Unauthorized(msg) => (StatusCode::UNAUTHORIZED, msg),
            Self::Conflict(msg) => (StatusCode::CONFLICT, msg),
        };
        (status, Json(serde_json::json!({"detail": detail}))).into_response()
    }
}

/// Parse a JSON request body, reporting errors in the same
/// `{"detail": ...}` shape (axum's default rejection body differs).
pub fn parse_json<T: serde::de::DeserializeOwned>(bytes: &[u8]) -> Result<T, ApiError> {
    serde_json::from_slice(bytes).map_err(|e| ApiError::unprocessable(format!("invalid JSON: {e}")))
}
