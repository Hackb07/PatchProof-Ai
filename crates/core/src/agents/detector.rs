//! Detector/triage agent (ports `backend/app/agents/detector.py`).

use std::collections::HashSet;

use crate::error::Result;
use crate::model::Finding;
use crate::store::Store;

use super::llm::LlmClient;

/// Dedupe raw findings and drop LLM-rejected ones.
pub async fn triage(store: &Store, llm: &LlmClient, scan_id: &str) -> Result<Vec<Finding>> {
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
        if keep_verdict(&verdict) {
            kept.push(f);
        } else {
            store.delete_finding(&f.id)?;
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

/// Parse `TRIAGE: KEEP|DROP`, preferring an explicitly labeled line so a
/// free-text mention of "drop" (e.g. "do not drop this") can't discard a
/// finding. Unlabeled replies keep the finding (matching the mock).
fn keep_verdict(output: &str) -> bool {
    for line in output.lines() {
        let upper = line.to_ascii_uppercase();
        if let Some(rest) = upper.strip_prefix("TRIAGE:") {
            return !rest.contains("DROP");
        }
    }
    true
}
