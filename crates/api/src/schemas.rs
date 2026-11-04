//! Request/response schemas (ports `backend/app/schemas.py`).

use std::cmp::Ordering;

use patchproof_core::store::Store;
use serde::{Deserialize, Serialize};

use crate::routes::ApiError;

#[derive(Debug, Deserialize)]
pub struct ScanCreate {
    pub repo_url: String,
    pub branch: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct ImportPayload {
    pub repo_url: Option<String>,
    pub branch: Option<String>,
}

#[derive(Debug, Deserialize)]
pub struct FileQuery {
    pub scan_id: String,
    pub path: String,
}

#[derive(Debug, Default, Deserialize)]
pub struct ScanListQuery {
    pub limit: Option<i64>,
    pub offset: Option<i64>,
}

#[derive(Debug, Clone, Serialize)]
pub struct VerificationOut {
    pub id: String,
    pub status: String,
    pub rescan_clean: bool,
    pub tests_passed: Option<bool>,
    pub test_log: String,
    pub notes: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct PatchOut {
    pub id: String,
    pub diff: String,
    pub summary: String,
    pub applied: bool,
    pub verifications: Vec<VerificationOut>,
}

#[derive(Debug, Clone, Serialize)]
pub struct FindingOut {
    pub id: String,
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
    pub patches: Vec<PatchOut>,
}

#[derive(Debug, Clone, Serialize)]
pub struct EvidenceOut {
    pub id: String,
    pub stage: String,
    pub actor: String,
    pub message: String,
    pub ref_id: String,
}

#[derive(Debug, Clone, Serialize)]
pub struct ScanOut {
    pub id: String,
    pub repo_url: String,
    pub branch: String,
    pub status: String,
    pub error: String,
    pub created_at: String,
    pub finished_at: Option<String>,
    pub findings: Vec<FindingOut>,
    pub evidence: Vec<EvidenceOut>,
}

/// Lightweight list entry: `GET /api/scans` must not serialize 50 full
/// reports (findings + diffs + logs) per request.
#[derive(Debug, Clone, Serialize)]
pub struct ScanSummary {
    pub id: String,
    pub repo_url: String,
    pub branch: String,
    pub status: String,
    pub error: String,
    pub created_at: String,
    pub finished_at: Option<String>,
    pub finding_count: usize,
    pub evidence_count: usize,
}

/// Serialize a full scan report: findings sorted by
/// `(-risk_score, file_path, line_no)`, evidence by `created_at`.
pub fn serialize_scan(store: &Store, scan_id: &str) -> Result<ScanOut, ApiError> {
    let scan = store
        .get_scan(scan_id)
        .map_err(|e| ApiError::internal(e.to_string()))?
        .ok_or_else(|| ApiError::not_found("scan not found"))?;
    let mut findings = store
        .list_findings(scan_id)
        .map_err(|e| ApiError::internal(e.to_string()))?;
    findings.sort_by(|a, b| {
        b.risk_score
            .partial_cmp(&a.risk_score)
            .unwrap_or(Ordering::Equal)
            .then_with(|| a.file_path.cmp(&b.file_path))
            .then_with(|| a.line_no.cmp(&b.line_no))
    });
    let mut out_findings = Vec::with_capacity(findings.len());
    for f in &findings {
        let patches = store
            .patches_for_finding(&f.id)
            .map_err(|e| ApiError::internal(e.to_string()))?;
        let mut out_patches = Vec::with_capacity(patches.len());
        for p in &patches {
            let verifications = store
                .verifications_for_patch(&p.id)
                .map_err(|e| ApiError::internal(e.to_string()))?;
            out_patches.push(PatchOut {
                id: p.id.clone(),
                diff: p.diff.clone(),
                summary: p.summary.clone(),
                applied: p.applied,
                verifications: verifications
                    .iter()
                    .map(|v| VerificationOut {
                        id: v.id.clone(),
                        status: v.status.clone(),
                        rescan_clean: v.rescan_clean,
                        tests_passed: v.tests_passed,
                        test_log: v.test_log.clone(),
                        notes: v.notes.clone(),
                    })
                    .collect(),
            });
        }
        out_findings.push(FindingOut {
            id: f.id.clone(),
            rule_id: f.rule_id.clone(),
            title: f.title.clone(),
            cwe: f.cwe.clone(),
            severity: f.severity.clone(),
            confidence: f.confidence.clone(),
            file_path: f.file_path.clone(),
            line_no: f.line_no,
            snippet: f.snippet.clone(),
            explanation: f.explanation.clone(),
            risk_score: f.risk_score,
            risk_rationale: f.risk_rationale.clone(),
            reproduced: f.reproduced,
            repro_log: f.repro_log.clone(),
            validated: f.validated,
            false_positive: f.false_positive,
            patches: out_patches,
        });
    }
    let mut evidence = store
        .list_evidence(scan_id)
        .map_err(|e| ApiError::internal(e.to_string()))?;
    evidence.sort_by(|a, b| a.created_at.cmp(&b.created_at));
    let out_evidence = evidence
        .iter()
        .map(|e| EvidenceOut {
            id: e.id.clone(),
            stage: e.stage.clone(),
            actor: e.actor.clone(),
            message: e.message.clone(),
            ref_id: e.ref_id.clone(),
        })
        .collect();
    Ok(ScanOut {
        id: scan.id,
        repo_url: scan.repo_url,
        branch: scan.branch,
        status: scan.status,
        error: scan.error,
        created_at: scan.created_at,
        finished_at: scan.finished_at,
        findings: out_findings,
        evidence: out_evidence,
    })
}

/// Serialize one lightweight list entry (counts only, no findings).
pub fn serialize_summary(
    store: &Store,
    scan: &patchproof_core::model::Scan,
) -> Result<ScanSummary, ApiError> {
    let finding_count = store
        .count_findings(&scan.id)
        .map_err(|e| ApiError::internal(e.to_string()))?;
    let evidence_count = store
        .count_evidence(&scan.id)
        .map_err(|e| ApiError::internal(e.to_string()))?;
    Ok(ScanSummary {
        id: scan.id.clone(),
        repo_url: scan.repo_url.clone(),
        branch: scan.branch.clone(),
        status: scan.status.clone(),
        error: scan.error.clone(),
        created_at: scan.created_at.clone(),
        finished_at: scan.finished_at.clone(),
        finding_count,
        evidence_count,
    })
}
