//! Central configuration (ports `backend/app/config.py`).
//!
//! Demo works offline with `LLM_MOCK=1` (default).

use std::path::{Path, PathBuf};

#[derive(Debug, Clone)]
pub struct Settings {
    pub app_name: String,
    pub database_url: String,
    pub repo_root: String,
    pub llm_mock: bool,
    pub meta_api_key: String,
    pub meta_api_base: String,
    pub meta_model: String,
    /// `auto` | `docker` | `subprocess`
    pub sandbox_backend: String,
    pub sandbox_timeout_s: u64,
    pub sandbox_image: String,
    pub cors_origins: String,
    /// Optional shared secret: when non-empty, `/api/scans` and
    /// `/api/github` require `Authorization: Bearer <key>` (or `X-API-Key`).
    pub api_key: String,
    /// Interface/port the HTTP API binds to.
    pub host: String,
    pub port: u16,
}

impl Default for Settings {
    fn default() -> Self {
        Self {
            app_name: "PatchProof AI".to_string(),
            database_url: "sqlite:///./patchproof.db".to_string(),
            repo_root: default_repo_root(),
            llm_mock: true,
            meta_api_key: String::new(),
            meta_api_base: "https://api.llama.meta.com/v1".to_string(),
            meta_model: "llama-4-scout".to_string(),
            sandbox_backend: "auto".to_string(),
            sandbox_timeout_s: 20,
            sandbox_image: "python:3.12-slim".to_string(),
            cors_origins: "http://localhost:5173,http://127.0.0.1:5173".to_string(),
            api_key: String::new(),
            host: "127.0.0.1".to_string(),
            port: 8000,
        }
    }
}

impl Settings {
    /// Load settings from the environment (after `dotenvy` `.env` loading).
    pub fn from_env() -> Self {
        dotenvy::dotenv().ok();
        let mut s = Self::default();
        if let Ok(v) = std::env::var("APP_NAME") {
            s.app_name = v;
        }
        if let Ok(v) = std::env::var("DATABASE_URL") {
            s.database_url = v;
        }
        if let Ok(v) = std::env::var("REPO_ROOT") {
            s.repo_root = v;
        }
        if let Ok(v) = std::env::var("LLM_MOCK") {
            s.llm_mock = parse_bool(&v, true);
        }
        if let Ok(v) = std::env::var("META_API_KEY") {
            s.meta_api_key = v;
        }
        if let Ok(v) = std::env::var("META_API_BASE") {
            s.meta_api_base = v;
        }
        if let Ok(v) = std::env::var("META_MODEL") {
            s.meta_model = v;
        }
        if let Ok(v) = std::env::var("SANDBOX_BACKEND") {
            s.sandbox_backend = v;
        }
        if let Ok(v) = std::env::var("SANDBOX_TIMEOUT_S") {
            if let Ok(n) = v.trim().parse::<u64>() {
                s.sandbox_timeout_s = n;
            }
        }
        if let Ok(v) = std::env::var("SANDBOX_IMAGE") {
            if !v.trim().is_empty() {
                s.sandbox_image = v.trim().to_string();
            }
        }
        if let Ok(v) = std::env::var("CORS_ORIGINS") {
            s.cors_origins = v;
        }
        if let Ok(v) = std::env::var("PATCHPROOF_API_KEY") {
            s.api_key = v.trim().to_string();
        }
        if let Ok(v) = std::env::var("HOST") {
            if !v.trim().is_empty() {
                s.host = v.trim().to_string();
            }
        }
        if let Ok(v) = std::env::var("PORT") {
            if let Ok(n) = v.trim().parse::<u16>() {
                s.port = n;
            }
        }
        s
    }

    /// Filesystem path of the SQLite database derived from `database_url`.
    pub fn database_path(&self) -> PathBuf {
        let mut url = self.database_url.trim().to_string();
        for prefix in ["sqlite://", "sqlite:"] {
            if let Some(rest) = url.strip_prefix(prefix) {
                url = rest.to_string();
                break;
            }
        }
        if let Some((base, _)) = url.split_once('?') {
            url = base.to_string();
        }
        // Tolerate `/C:/...` style absolute Windows paths.
        if url.len() >= 3 && url.starts_with('/') && url.as_bytes()[2] == b':' {
            url = url[1..].to_string();
        }
        PathBuf::from(url)
    }

    /// Comma-separated CORS origins as a trimmed list.
    pub fn cors_list(&self) -> Vec<String> {
        self.cors_origins
            .split(',')
            .map(|o| o.trim().to_string())
            .filter(|o| !o.is_empty())
            .collect()
    }
}

/// Default repo checkout dir inside the OS temp directory (per-user on
/// every OS: `%TEMP%` on Windows, `$TMPDIR` or `/tmp` elsewhere).
pub fn default_repo_root() -> String {
    std::env::temp_dir()
        .join("patchproof")
        .join("repos")
        .to_string_lossy()
        .to_string()
}

/// Normalize a user-supplied local path: strip `file://`, tolerate `/C:/...`
/// absolute Windows paths (also produced from `file:///C:/...` URLs).
pub fn normalize_local_path(raw: &str) -> String {
    let mut local = raw.trim().to_string();
    while let Some(rest) = local.strip_prefix("file://") {
        local = rest.to_string();
    }
    if local.len() >= 3 && local.starts_with('/') && local.as_bytes()[2] == b':' {
        local = local[1..].to_string();
    }
    local
}

/// True when `repo_url` points at a directory on this machine (a scan of
/// the operator's own files, as opposed to a remote clone of untrusted
/// code). Used to decide whether target-repo tests may run on the host.
pub fn is_local_scan_repo(repo_url: &str) -> bool {
    Path::new(&normalize_local_path(repo_url)).is_dir()
}

fn parse_bool(raw: &str, default: bool) -> bool {
    match raw.trim().to_ascii_lowercase().as_str() {
        "1" | "true" | "yes" | "y" | "on" => true,
        "0" | "false" | "no" | "n" | "off" | "" => false,
        _ => default,
    }
}
