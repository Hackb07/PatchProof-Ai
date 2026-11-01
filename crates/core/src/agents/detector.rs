//! Detector/triage agent (ports `backend/app/agents/detector.py`).

use std::collections::HashSet;

use crate::error::Result;
use crate::model::Finding;
use crate::store::Store;

use super::llm::LlmClient;

/// Dedupe raw findings and drop LLM-rejected ones.
pub async fn triage(
    store: &Store,
    llm: &LlmClient,
    scan_id: &str,
) -> Result<Vec<Finding>> {
    let findings = store.list_findings(scan_id)?;
    let total = findings.len();
    let mut kept = Vec::new();
    let mut seen: HashSet<(String, String, i64)> = HashSet::new();
    for f in findings {
        let key = (f.rule_id.clone(), f.file_path.clone(), f.line_no);
        if !seen.insert(key) {
            store.delete_finding(&f.id)?;
            continue;
        }
        let verdict = llm
            .chat(
                "You triage static-analysis findings. Reply TRIAGE: KEEP or TRIAGE: DROP with a reason.",
                &format!(
                    "Rule {} {} at {}:{}\n{}\n{}",
                    f.rule_id, f.title, f.file_path, f.line_no, f.snippet, f.explanation
                ),
                800,
            )
            .await
            .output;
        if verdict.to_ascii_uppercase().contains("DROP") {
            store.delete_finding(&f.id)?;
        } else {
            kept.push(f);
        }
    }
    store.add_evidence(
        scan_id,
        "triage",
        "detector",
        &format!("Triage complete: {}/{} findings kept", kept.len(), total),
        "",
    )?;
    Ok(kept)
}
