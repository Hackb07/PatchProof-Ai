//! Validator agent (ports `backend/app/agents/validator.py`).

use crate::error::Result;
use crate::model::Finding;
use crate::store::Store;
use crate::truncate_chars;

use super::llm::LlmClient;

/// Confirm findings using repro evidence plus code context.
pub async fn validate(store: &Store, llm: &LlmClient, scan_id: &str) -> Result<Vec<Finding>> {
    let findings = store.list_findings(scan_id)?;
    for f in &findings {
        let reproduced = if f.reproduced { "True" } else { "False" };
        let reply = llm
            .chat(
                "You validate security findings. Reply VERDICT: TRUE_POSITIVE or VERDICT: FALSE_POSITIVE with REASON.",
                &format!(
                    "{} at {}:{}\n{}\nReproduced: {}. Repro log:\n{}",
                    f.title,
                    f.file_path,
                    f.line_no,
                    f.snippet,
                    reproduced,
                    truncate_chars(&f.repro_log, 1500)
                ),
                800,
            )
            .await
            .output;
        if is_false_positive(&reply) {
            store.update_finding_validation(&f.id, false, true)?;
        } else {
            store.update_finding_validation(&f.id, true, false)?;
        }
    }
    store.add_evidence(
        scan_id,
        "triage",
        "validator",
        "Validation pass complete",
        "",
    )?;
    Ok(findings)
}

/// Parse `VERDICT: TRUE_POSITIVE|FALSE_POSITIVE`, preferring an explicitly
/// labeled line so free-text mentions can't flip the verdict. Unlabeled
/// replies confirm the finding (matching the mock).
fn is_false_positive(output: &str) -> bool {
    for line in output.lines() {
        let upper = line.to_ascii_uppercase();
        if let Some(rest) = upper.strip_prefix("VERDICT:") {
            return rest.contains("FALSE_POSITIVE");
        }
    }
    false
}
