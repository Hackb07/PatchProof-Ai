//! Apply unified diffs to a repo checkout (ports
//! `backend/app/patcher/applier.py`).

use std::path::Path;
use std::sync::OnceLock;

use regex::Regex;

/// Apply a unified diff produced by the patcher. Returns true on success.
pub fn apply_diff(repo_path: &str, diff: &str) -> bool {
    let (target_rel, hunks) = parse(diff);
    if target_rel.is_empty() || hunks.is_empty() {
        return false;
    }
    let target = Path::new(repo_path).join(&target_rel);
    let bytes = match std::fs::read(&target) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let content = String::from_utf8_lossy(&bytes).to_string();
    let mut lines = split_keepends(&content);
    // Apply hunks in reverse so line numbers stay valid.
    let mut order: Vec<usize> = (0..hunks.len()).collect();
    order.sort_by_key(|&i| std::cmp::Reverse(hunks[i].0));
    for i in order {
        let (start, old_count, new_lines) = &hunks[i];
        let idx = (*start as usize).saturating_sub(1).min(lines.len());
        let end = (idx + *old_count as usize).min(lines.len());
        let replacement: Vec<String> = new_lines.to_vec();
        lines.splice(idx..end, replacement);
    }
    std::fs::write(&target, lines.concat()).is_ok()
}

fn split_keepends(s: &str) -> Vec<String> {
    if s.is_empty() {
        return Vec::new();
    }
    s.split_inclusive('\n').map(|l| l.to_string()).collect()
}

fn hunk_re() -> &'static Regex {
    static CELL: OnceLock<Regex> = OnceLock::new();
    CELL.get_or_init(|| Regex::new(r#"^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@"#).unwrap())
}

fn parse(diff: &str) -> (String, Vec<(usize, usize, Vec<String>)>) {
    let mut target = String::new();
    let mut hunks: Vec<(usize, usize, Vec<String>)> = Vec::new();
    let mut current: Option<usize> = None;
    for line in split_keepends(diff) {
        if let Some(rest) = line.strip_prefix("+++ b/") {
            target = rest.trim().to_string();
        } else if line.starts_with("@@") {
            if let Some(cap) = hunk_re().captures(&line) {
                let start: usize = cap.get(1).and_then(|m| m.as_str().parse().ok()).unwrap_or(1);
                let old_count: usize = cap
                    .get(2)
                    .map(|m| m.as_str().parse().unwrap_or(1))
                    .unwrap_or(1);
                hunks.push((start, old_count, Vec::new()));
                current = Some(hunks.len() - 1);
            }
        } else if let Some(i) = current {
            if line.starts_with('+') && !line.starts_with("+++") {
                hunks[i].2.push(line[1..].to_string());
            } else if line.starts_with(' ') || line.starts_with('\\') {
                if line.starts_with(' ') {
                    hunks[i].2.push(line[1..].to_string());
                } else {
                    hunks[i].2.push(String::new());
                }
            } else if line.starts_with('-') && !line.starts_with("---") {
                // Removed line: skip (old_count already accounts for it).
            }
        }
    }
    (target, hunks)
}
