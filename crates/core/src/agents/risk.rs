//! Risk assessor agent (ports `backend/app/agents/risk_assessor.py`).

use std::sync::OnceLock;

use regex::Regex;

use crate::error::Result;
use crate::model::Finding;
use crate::store::Store;
use crate::truncate_chars;

use super::llm::LlmClient;

pub fn severity_prior(severity: &str) -> f64 {
    match severity {
        "critical" => 9.0,
        "high" => 7.5,
        "medium" => 5.0,
        "low" => 2.5,
        _ => 5.0,
    }
}

/// Score each finding 0-10 with a rationale.
pub async fn assess(
    store: &Store,
    llm: &LlmClient,
    scan_id: &str,
) -> Result<Vec<Finding>> {
    let findings = store.list_findings(scan_id)?;
    for f in &findings {
        let (reply, score) = if llm.is_mock() {
            let mut score = severity_prior(&f.severity);
            if f.confidence == "low" {
                score = (score - 1.5).max(1.0);
            } else if f.confidence == "high" {
                score = (score + 0.5).min(10.0);
            }
            let reply = format!(
                "RISK_SCORE: {}\nRATIONALE: Mock heuristic: {} severity, {} confidence, {}. Connect a Meta model for contextual scoring.",
                fmt_score(score),
                f.severity,
                f.confidence,
                f.cwe
            );
            (reply, score)
        } else {
            let reply = llm
                .chat(
                    "You are a security risk assessor. Reply with RISK_SCORE: <0-10> and RATIONALE: <one paragraph>.",
                    &format!(
                        "Severity {} confidence {}. {} ({}) at {}:{}\n{}\n{}",
                        f.severity,
                        f.confidence,
                        f.title,
                        f.cwe,
                        f.file_path,
                        f.line_no,
                        f.snippet,
                        f.explanation
                    ),
                    800,
                )
                .await
                .output;
            let mut score = parse_score(&reply).unwrap_or_else(|| severity_prior(&f.severity));
            if f.confidence == "low" {
                score = (score - 1.5).max(1.0);
            }
            (reply, score)
        };
        let clamped = score.clamp(0.0, 10.0);
        let rounded = (clamped * 10.0).round() / 10.0;
        store.update_finding_risk(&f.id, rounded, &truncate_chars(reply.trim(), 2000))?;
    }
    store.add_evidence(
        scan_id,
        "risk",
        "risk-assessor",
        &format!("Risk scoring complete for {} findings", findings.len()),
        "",
    )?;
    Ok(findings)
}

fn parse_score(text: &str) -> Option<f64> {
    static CELL: OnceLock<Regex> = OnceLock::new();
    let re =
        CELL.get_or_init(|| Regex::new(r"(?i)RISK_SCORE:\s*([0-9]+(?:\.[0-9]+)?)").unwrap());
    re.captures(text)
        .and_then(|c| c.get(1))
        .and_then(|m| m.as_str().parse::<f64>().ok())
}

/// Match Python `str(float)` for whole-number scores (`5.0`, not `5`).
fn fmt_score(score: f64) -> String {
    if score.fract() == 0.0 {
        format!("{score:.1}")
    } else {
        format!("{score}")
    }
}
