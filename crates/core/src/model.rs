//! Data model (ports `backend/app/models.py`).
//!
//! `Scan` 1-n `Finding` 1-n `Patch` 1-n `Verification`, plus append-only
//! `Evidence` timeline rows.

/// 12 lowercase hex chars, like the Python `_uid()`.
pub fn new_id() -> String {
    uuid::Uuid::new_v4().simple().to_string()[..12].to_string()
}

/// UTC timestamp with nanosecond precision (lexicographically sortable).
pub fn now_rfc3339() -> String {
    chrono::Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Nanos, true)
}

#[derive(Debug, Clone)]
pub struct Scan {
    pub id: String,
    pub repo_url: String,
    pub branch: String,
    /// queued|scanning|triaging|patching|verifying|done|failed|cancelled
    pub status: String,
    pub created_at: String,
    pub finished_at: Option<String>,
    pub repo_path: String,
    pub error: String,
}

#[derive(Debug, Clone)]
pub struct Finding {
    pub id: String,
    pub scan_id: String,
    pub rule_id: String,
    pub title: String,
    pub cwe: String,
    pub severity: String,
    pub confidence: String,
    pub file_path: String,
    pub line_no: i64,
    pub snippet: String,
    pub explanation: String,
    pub risk_score: f64,
    pub risk_rationale: String,
    pub reproduced: bool,
    pub repro_log: String,
    pub validated: bool,
    pub false_positive: bool,
}

#[derive(Debug, Clone)]
pub struct Patch {
    pub id: String,
    pub finding_id: String,
    pub diff: String,
    pub summary: String,
    pub applied: bool,
    pub created_at: String,
}

#[derive(Debug, Clone)]
pub struct Verification {
    pub id: String,
    pub patch_id: String,
    /// fixed|unfixed|inconclusive
    pub status: String,
    pub rescan_clean: bool,
    pub tests_passed: Option<bool>,
    pub test_log: String,
    pub notes: String,
    pub created_at: String,
}

#[derive(Debug, Clone)]
pub struct Evidence {
    pub id: String,
    pub scan_id: String,
    /// clone|scan|triage|risk|repro|patch|verify|done
    pub stage: String,
    pub actor: String,
    pub message: String,
    pub ref_id: String,
    pub created_at: String,
}
