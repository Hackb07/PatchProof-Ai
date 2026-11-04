//! Apply unified diffs to a repo checkout (ports
//! `backend/app/patcher/applier.py`).
//!
//! Hunks are matched by content (context + removed lines), not just by line
//! number: after earlier patches shift a file, later hunks still land on the
//! right code instead of corrupting it.

use std::path::Path;
use std::sync::OnceLock;

use regex::Regex;

/// How far (in lines) from a hunk's recorded position to search for its
/// expected content before giving up.
const SEARCH_RADIUS: usize = 80;

struct Hunk {
    start: usize,
    old_lines: Vec<String>,
    new_lines: Vec<String>,
}

/// Apply a unified diff produced by the patcher. Returns true on success.
///
/// Every hunk must match its expected old lines at (or near) the recorded
/// position; a hunk that matches nowhere fails the whole application, so a
/// stale diff can never silently rewrite the wrong code.
pub fn apply_diff(repo_path: &str, diff: &str) -> bool {
    let (target_rel, hunks) = parse(diff);
    if target_rel.is_empty() || hunks.is_empty() {
        return false;
    }
    // Defense in depth: never write outside the checkout or through a link.
    if target_rel.contains("..") || Path::new(&target_rel).is_absolute() {
        return false;
    }
    let target = Path::new(repo_path).join(&target_rel);
    if target.is_symlink() {
        return false;
    }
    let bytes = match std::fs::read(&target) {
        Ok(b) => b,
        Err(_) => return false,
    };
    let content = String::from_utf8_lossy(&bytes).to_string();
    let mut lines = split_keepends(&content);
    // Apply bottom-up so earlier hunk positions stay valid; each hunk is
    // still content-verified before splicing.
    let mut order: Vec<usize> = (0..hunks.len()).collect();
    order.sort_by_key(|&i| std::cmp::Reverse(hunks[i].start));
    for i in order {
        if !apply_hunk(&mut lines, &hunks[i]) {
            return false;
        }
    }
    std::fs::write(&target, lines.concat()).is_ok()
}

fn apply_hunk(lines: &mut Vec<String>, hunk: &Hunk) -> bool {
    if hunk.old_lines.is_empty() {
        let idx = hunk.start.saturating_sub(1).min(lines.len());
        lines.splice(idx..idx, hunk.new_lines.clone());
        return true;
    }
    let expected = hunk.start.saturating_sub(1).min(lines.len());
    if matches_at(lines, expected, &hunk.old_lines) {
        splice_at(lines, expected, hunk);
        return true;
    }
    // Search outward from the expected position: earlier patches may have
    // shifted the hunk's content.
    for dist in 1..=SEARCH_RADIUS {
        let lo = expected.saturating_sub(dist);
        if matches_at(lines, lo, &hunk.old_lines) {
            splice_at(lines, lo, hunk);
            return true;
        }
        let hi = expected + dist;
        if matches_at(lines, hi, &hunk.old_lines) {
            splice_at(lines, hi, hunk);
            return true;
        }
    }
    false
}

fn matches_at(lines: &[String], idx: usize, old: &[String]) -> bool {
    if idx + old.len() > lines.len() {
        return false;
    }
    lines[idx..idx + old.len()] == *old
}

fn splice_at(lines: &mut Vec<String>, idx: usize, hunk: &Hunk) {
    let end = (idx + hunk.old_lines.len()).min(lines.len());
    lines.splice(idx..end, hunk.new_lines.clone());
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

fn parse(diff: &str) -> (String, Vec<Hunk>) {
    let mut target = String::new();
    let mut hunks: Vec<Hunk> = Vec::new();
    let mut current: Option<usize> = None;
    for line in split_keepends(diff) {
        if let Some(rest) = line.strip_prefix("+++ b/") {
            target = rest.trim().to_string();
        } else if line.starts_with("@@") {
            if let Some(cap) = hunk_re().captures(&line) {
                let start: usize = cap
                    .get(1)
                    .and_then(|m| m.as_str().parse().ok())
                    .unwrap_or(1);
                hunks.push(Hunk {
                    start,
                    old_lines: Vec::new(),
                    new_lines: Vec::new(),
                });
                current = Some(hunks.len() - 1);
            }
        } else if let Some(i) = current {
            if line.starts_with('+') && !line.starts_with("+++") {
                hunks[i].new_lines.push(line[1..].to_string());
            } else if let Some(stripped) = line.strip_prefix(' ') {
                let stripped = stripped.to_string();
                hunks[i].old_lines.push(stripped.clone());
                hunks[i].new_lines.push(stripped);
            } else if line.starts_with('-') && !line.starts_with("---") {
                hunks[i].old_lines.push(line[1..].to_string());
            }
            // `\ No newline at end of file` markers carry no content.
        }
    }
    (target, hunks)
}
