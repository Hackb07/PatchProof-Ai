//! SQLite storage (ports `backend/app/store.py`).
//!
//! One short-lived connection per operation with a busy timeout; this keeps
//! the async API handlers free of shared connection state.

use std::path::{Path, PathBuf};

use rusqlite::{params, Connection, OptionalExtension};

use crate::config::Settings;
use crate::error::Result;
use crate::model::{new_id, now_rfc3339, Evidence, Finding, Patch, Scan, Verification};
use crate::scanner::rules::RawFinding;

const SCHEMA: &str = r#"
CREATE TABLE IF NOT EXISTS scans (
    id TEXT PRIMARY KEY,
    repo_url TEXT NOT NULL,
    branch TEXT NOT NULL DEFAULT 'HEAD',
    status TEXT NOT NULL DEFAULT 'queued',
    created_at TEXT NOT NULL,
    finished_at TEXT,
    repo_path TEXT NOT NULL DEFAULT '',
    error TEXT NOT NULL DEFAULT ''
);
CREATE TABLE IF NOT EXISTS findings (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    rule_id TEXT NOT NULL,
    title TEXT NOT NULL,
    cwe TEXT NOT NULL DEFAULT '',
    severity TEXT NOT NULL DEFAULT 'medium',
    confidence TEXT NOT NULL DEFAULT 'medium',
    file_path TEXT NOT NULL,
    line_no INTEGER NOT NULL,
    snippet TEXT NOT NULL DEFAULT '',
    explanation TEXT NOT NULL DEFAULT '',
    risk_score REAL NOT NULL DEFAULT 0.0,
    risk_rationale TEXT NOT NULL DEFAULT '',
    reproduced INTEGER NOT NULL DEFAULT 0,
    repro_log TEXT NOT NULL DEFAULT '',
    validated INTEGER NOT NULL DEFAULT 0,
    false_positive INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE IF NOT EXISTS patches (
    id TEXT PRIMARY KEY,
    finding_id TEXT NOT NULL,
    diff TEXT NOT NULL DEFAULT '',
    summary TEXT NOT NULL DEFAULT '',
    applied INTEGER NOT NULL DEFAULT 0,
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS verifications (
    id TEXT PRIMARY KEY,
    patch_id TEXT NOT NULL,
    status TEXT NOT NULL DEFAULT 'inconclusive',
    rescan_clean INTEGER NOT NULL DEFAULT 0,
    tests_passed INTEGER,
    test_log TEXT NOT NULL DEFAULT '',
    notes TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS evidence (
    id TEXT PRIMARY KEY,
    scan_id TEXT NOT NULL,
    stage TEXT NOT NULL,
    actor TEXT NOT NULL DEFAULT 'system',
    message TEXT NOT NULL DEFAULT '',
    ref_id TEXT NOT NULL DEFAULT '',
    created_at TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_findings_scan ON findings(scan_id);
CREATE INDEX IF NOT EXISTS idx_findings_rule ON findings(rule_id);
CREATE INDEX IF NOT EXISTS idx_patches_finding ON patches(finding_id);
CREATE INDEX IF NOT EXISTS idx_verifications_patch ON verifications(patch_id);
CREATE INDEX IF NOT EXISTS idx_evidence_scan ON evidence(scan_id);
"#;

#[derive(Debug, Clone)]
pub struct Store {
    db_path: PathBuf,
}

impl Store {
    pub fn new(db_path: &Path) -> Self {
        Self {
            db_path: db_path.to_path_buf(),
        }
    }

    pub fn from_settings(settings: &Settings) -> Self {
        Self::new(&settings.database_path())
    }

    fn conn(&self) -> Result<Connection> {
        let conn = Connection::open(&self.db_path)?;
        conn.busy_timeout(std::time::Duration::from_secs(5))?;
        Ok(conn)
    }

    pub fn init_db(&self) -> Result<()> {
        if let Some(parent) = self.db_path.parent() {
            if !parent.as_os_str().is_empty() {
                std::fs::create_dir_all(parent)?;
            }
        }
        let conn = self.conn()?;
        conn.execute_batch(SCHEMA)?;
        // Concurrent pipelines + API handlers share this file; WAL keeps
        // readers from blocking writers (with the 5s busy timeout above).
        conn.execute_batch("PRAGMA journal_mode=WAL;")?;
        Ok(())
    }

    // -- scans -----------------------------------------------------------

    pub fn create_scan(&self, repo_url: &str, branch: &str) -> Result<Scan> {
        // 12-hex ids can theoretically collide; retry with a fresh id.
        let mut last_err = None;
        for _ in 0..3 {
            let scan = Scan {
                id: new_id(),
                repo_url: repo_url.to_string(),
                branch: branch.to_string(),
                status: "queued".to_string(),
                created_at: now_rfc3339(),
                finished_at: None,
                repo_path: String::new(),
                error: String::new(),
            };
            let conn = self.conn()?;
            match conn.execute(
                "INSERT INTO scans (id, repo_url, branch, status, created_at, finished_at, repo_path, error)
                 VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                params![
                    scan.id,
                    scan.repo_url,
                    scan.branch,
                    scan.status,
                    scan.created_at,
                    scan.finished_at,
                    scan.repo_path,
                    scan.error
                ],
            ) {
                Ok(_) => return Ok(scan),
                Err(e) if is_constraint_violation(&e) => last_err = Some(e),
                Err(e) => return Err(e.into()),
            }
        }
        Err(last_err
            .map(crate::error::CoreError::from)
            .unwrap_or_else(|| crate::error::CoreError::Other("scan id collision".to_string())))
    }

    pub fn get_scan(&self, scan_id: &str) -> Result<Option<Scan>> {
        let conn = self.conn()?;
        let row = conn
            .query_row(
                "SELECT id, repo_url, branch, status, created_at, finished_at, repo_path, error
                 FROM scans WHERE id = ?",
                params![scan_id],
                scan_from_row,
            )
            .optional()?;
        Ok(row)
    }

    pub fn list_scans(&self, limit: i64) -> Result<Vec<Scan>> {
        self.list_scans_paginated(limit, 0)
    }

    pub fn count_scans(&self) -> Result<usize> {
        let conn = self.conn()?;
        let n: i64 = conn.query_row("SELECT COUNT(*) FROM scans", [], |row| row.get(0))?;
        Ok(n.max(0) as usize)
    }

    pub fn list_scans_paginated(&self, limit: i64, offset: i64) -> Result<Vec<Scan>> {
        let limit = limit.clamp(1, 200);
        let offset = offset.max(0);
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, repo_url, branch, status, created_at, finished_at, repo_path, error
             FROM scans ORDER BY created_at DESC, rowid DESC LIMIT ? OFFSET ?",
        )?;
        let rows = stmt.query_map(params![limit, offset], scan_from_row)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    /// Delete a scan and all its findings, patches, verifications, and
    /// evidence. Returns true when a scan existed.
    pub fn delete_scan(&self, scan_id: &str) -> Result<bool> {
        if self.get_scan(scan_id)?.is_none() {
            return Ok(false);
        }
        self.clear_scan_results(scan_id)?;
        let conn = self.conn()?;
        conn.execute("DELETE FROM evidence WHERE scan_id = ?", params![scan_id])?;
        conn.execute("DELETE FROM scans WHERE id = ?", params![scan_id])?;
        Ok(true)
    }

    /// Mark a running scan as cancelled. Returns true when the status was
    /// changed; terminal scans (`done`/`failed`/`cancelled`) are untouched.
    pub fn cancel_scan(&self, scan_id: &str) -> Result<bool> {
        let conn = self.conn()?;
        let changed = conn.execute(
            "UPDATE scans SET status = 'cancelled', error = 'cancelled by user',
                 finished_at = ?
             WHERE id = ? AND status NOT IN ('done', 'failed', 'cancelled')",
            params![now_rfc3339(), scan_id],
        )?;
        Ok(changed > 0)
    }

    /// True when the pipeline should stop: scan deleted or cancelled.
    pub fn is_aborted(&self, scan_id: &str) -> bool {
        match self.get_scan(scan_id) {
            Ok(Some(s)) => s.status == "cancelled",
            Ok(None) => true,
            Err(_) => false,
        }
    }

    pub fn update_scan_status(&self, scan_id: &str, status: &str) -> Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "UPDATE scans SET status = ? WHERE id = ?",
            params![status, scan_id],
        )?;
        Ok(())
    }

    pub fn set_scan_repo_path(&self, scan_id: &str, repo_path: &str) -> Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "UPDATE scans SET repo_path = ? WHERE id = ?",
            params![repo_path, scan_id],
        )?;
        Ok(())
    }

    pub fn set_scan_done(&self, scan_id: &str) -> Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "UPDATE scans SET status = 'done', finished_at = ? WHERE id = ?",
            params![now_rfc3339(), scan_id],
        )?;
        Ok(())
    }

    pub fn set_scan_failed(&self, scan_id: &str, error: &str) -> Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "UPDATE scans SET status = 'failed', error = ?, finished_at = ? WHERE id = ?",
            params![error, now_rfc3339(), scan_id],
        )?;
        Ok(())
    }

    pub fn reset_scan_queued(&self, scan_id: &str) -> Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "UPDATE scans SET status = 'queued', error = '', finished_at = NULL WHERE id = ?",
            params![scan_id],
        )?;
        Ok(())
    }

    /// Delete a scan's findings, patches, and verifications (for reruns).
    /// Evidence rows are kept as the audit trail.
    pub fn clear_scan_results(&self, scan_id: &str) -> Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "DELETE FROM verifications WHERE patch_id IN
             (SELECT p.id FROM patches p JOIN findings f ON p.finding_id = f.id
              WHERE f.scan_id = ?)",
            params![scan_id],
        )?;
        conn.execute(
            "DELETE FROM patches WHERE finding_id IN
             (SELECT id FROM findings WHERE scan_id = ?)",
            params![scan_id],
        )?;
        conn.execute("DELETE FROM findings WHERE scan_id = ?", params![scan_id])?;
        Ok(())
    }

    /// Mark scans left mid-pipeline by a server restart as failed.
    /// Returns the number of scans recovered.
    pub fn fail_stale_scans(&self) -> Result<usize> {
        let conn = self.conn()?;
        let changed = conn.execute(
            "UPDATE scans SET status = 'failed',
                 error = 'interrupted by server restart',
                 finished_at = ?
             WHERE status NOT IN ('done', 'failed', 'cancelled')",
            params![now_rfc3339()],
        )?;
        Ok(changed)
    }

    // -- findings --------------------------------------------------------

    pub fn create_finding(
        &self,
        scan_id: &str,
        raw: &RawFinding,
        file_path: &str,
    ) -> Result<Finding> {
        let finding = Finding {
            id: new_id(),
            scan_id: scan_id.to_string(),
            rule_id: raw.rule_id.clone(),
            title: raw.title.clone(),
            cwe: raw.cwe.clone(),
            severity: raw.severity.clone(),
            confidence: raw.confidence.clone(),
            file_path: file_path.to_string(),
            line_no: raw.line_no as i64,
            snippet: raw.snippet.clone(),
            explanation: raw.explanation.clone(),
            risk_score: 0.0,
            risk_rationale: String::new(),
            reproduced: false,
            repro_log: String::new(),
            validated: false,
            false_positive: false,
        };
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO findings (id, scan_id, rule_id, title, cwe, severity, confidence,
                 file_path, line_no, snippet, explanation, risk_score, risk_rationale,
                 reproduced, repro_log, validated, false_positive)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                finding.id,
                finding.scan_id,
                finding.rule_id,
                finding.title,
                finding.cwe,
                finding.severity,
                finding.confidence,
                finding.file_path,
                finding.line_no,
                finding.snippet,
                finding.explanation,
                finding.risk_score,
                finding.risk_rationale,
                finding.reproduced,
                finding.repro_log,
                finding.validated,
                finding.false_positive
            ],
        )?;
        Ok(finding)
    }

    pub fn get_finding(&self, finding_id: &str) -> Result<Option<Finding>> {
        let conn = self.conn()?;
        let row = conn
            .query_row(FINDING_SELECT_ONE, params![finding_id], finding_from_row)
            .optional()?;
        Ok(row)
    }

    pub fn list_findings(&self, scan_id: &str) -> Result<Vec<Finding>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, scan_id, rule_id, title, cwe, severity, confidence, file_path,
                    line_no, snippet, explanation, risk_score, risk_rationale, reproduced,
                    repro_log, validated, false_positive
             FROM findings WHERE scan_id = ? ORDER BY rowid",
        )?;
        let rows = stmt.query_map(params![scan_id], finding_from_row)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    pub fn list_active_findings(&self, scan_id: &str) -> Result<Vec<Finding>> {
        Ok(self
            .list_findings(scan_id)?
            .into_iter()
            .filter(|f| !f.false_positive)
            .collect())
    }

    pub fn count_findings(&self, scan_id: &str) -> Result<usize> {
        let conn = self.conn()?;
        let n: i64 = conn.query_row(
            "SELECT COUNT(*) FROM findings WHERE scan_id = ?",
            params![scan_id],
            |row| row.get(0),
        )?;
        Ok(n.max(0) as usize)
    }

    pub fn count_evidence(&self, scan_id: &str) -> Result<usize> {
        let conn = self.conn()?;
        let n: i64 = conn.query_row(
            "SELECT COUNT(*) FROM evidence WHERE scan_id = ?",
            params![scan_id],
            |row| row.get(0),
        )?;
        Ok(n.max(0) as usize)
    }

    pub fn delete_finding(&self, finding_id: &str) -> Result<()> {
        let conn = self.conn()?;
        conn.execute("DELETE FROM findings WHERE id = ?", params![finding_id])?;
        Ok(())
    }

    pub fn update_finding_risk(&self, finding_id: &str, score: f64, rationale: &str) -> Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "UPDATE findings SET risk_score = ?, risk_rationale = ? WHERE id = ?",
            params![score, rationale, finding_id],
        )?;
        Ok(())
    }

    pub fn update_finding_repro(
        &self,
        finding_id: &str,
        reproduced: bool,
        log: &str,
    ) -> Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "UPDATE findings SET reproduced = ?, repro_log = ? WHERE id = ?",
            params![reproduced, log, finding_id],
        )?;
        Ok(())
    }

    pub fn update_finding_validation(
        &self,
        finding_id: &str,
        validated: bool,
        false_positive: bool,
    ) -> Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "UPDATE findings SET validated = ?, false_positive = ? WHERE id = ?",
            params![validated, false_positive, finding_id],
        )?;
        Ok(())
    }

    // -- patches ---------------------------------------------------------

    pub fn create_patch(&self, finding_id: &str, diff: &str, summary: &str) -> Result<Patch> {
        let patch = Patch {
            id: new_id(),
            finding_id: finding_id.to_string(),
            diff: diff.to_string(),
            summary: summary.to_string(),
            applied: false,
            created_at: now_rfc3339(),
        };
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO patches (id, finding_id, diff, summary, applied, created_at)
             VALUES (?, ?, ?, ?, ?, ?)",
            params![
                patch.id,
                patch.finding_id,
                patch.diff,
                patch.summary,
                patch.applied,
                patch.created_at
            ],
        )?;
        Ok(patch)
    }

    pub fn patches_for_finding(&self, finding_id: &str) -> Result<Vec<Patch>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, finding_id, diff, summary, applied, created_at
             FROM patches WHERE finding_id = ? ORDER BY rowid",
        )?;
        let rows = stmt.query_map(params![finding_id], patch_from_row)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    pub fn scan_patches(&self, scan_id: &str) -> Result<Vec<Patch>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT p.id, p.finding_id, p.diff, p.summary, p.applied, p.created_at
             FROM patches p JOIN findings f ON p.finding_id = f.id
             WHERE f.scan_id = ? ORDER BY p.rowid",
        )?;
        let rows = stmt.query_map(params![scan_id], patch_from_row)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    pub fn set_patch_applied(&self, patch_id: &str, applied: bool) -> Result<()> {
        let conn = self.conn()?;
        conn.execute(
            "UPDATE patches SET applied = ? WHERE id = ?",
            params![applied, patch_id],
        )?;
        Ok(())
    }

    // -- verifications ---------------------------------------------------

    pub fn create_verification(
        &self,
        patch_id: &str,
        status: &str,
        rescan_clean: bool,
        tests_passed: Option<bool>,
        test_log: &str,
        notes: &str,
    ) -> Result<Verification> {
        let verification = Verification {
            id: new_id(),
            patch_id: patch_id.to_string(),
            status: status.to_string(),
            rescan_clean,
            tests_passed,
            test_log: test_log.to_string(),
            notes: notes.to_string(),
            created_at: now_rfc3339(),
        };
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO verifications (id, patch_id, status, rescan_clean, tests_passed,
                 test_log, notes, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            params![
                verification.id,
                verification.patch_id,
                verification.status,
                verification.rescan_clean,
                verification.tests_passed,
                verification.test_log,
                verification.notes,
                verification.created_at
            ],
        )?;
        Ok(verification)
    }

    pub fn verifications_for_patch(&self, patch_id: &str) -> Result<Vec<Verification>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, patch_id, status, rescan_clean, tests_passed, test_log, notes, created_at
             FROM verifications WHERE patch_id = ? ORDER BY rowid",
        )?;
        let rows = stmt.query_map(params![patch_id], verification_from_row)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    pub fn scan_verifications(&self, scan_id: &str) -> Result<Vec<Verification>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT v.id, v.patch_id, v.status, v.rescan_clean, v.tests_passed, v.test_log,
                    v.notes, v.created_at
             FROM verifications v JOIN patches p ON v.patch_id = p.id
             JOIN findings f ON p.finding_id = f.id
             WHERE f.scan_id = ? ORDER BY v.rowid",
        )?;
        let rows = stmt.query_map(params![scan_id], verification_from_row)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }

    // -- evidence --------------------------------------------------------

    pub fn add_evidence(
        &self,
        scan_id: &str,
        stage: &str,
        actor: &str,
        message: &str,
        ref_id: &str,
    ) -> Result<Evidence> {
        let evidence = Evidence {
            id: new_id(),
            scan_id: scan_id.to_string(),
            stage: stage.to_string(),
            actor: actor.to_string(),
            message: message.to_string(),
            ref_id: ref_id.to_string(),
            created_at: now_rfc3339(),
        };
        let conn = self.conn()?;
        conn.execute(
            "INSERT INTO evidence (id, scan_id, stage, actor, message, ref_id, created_at)
             VALUES (?, ?, ?, ?, ?, ?, ?)",
            params![
                evidence.id,
                evidence.scan_id,
                evidence.stage,
                evidence.actor,
                evidence.message,
                evidence.ref_id,
                evidence.created_at
            ],
        )?;
        Ok(evidence)
    }

    pub fn list_evidence(&self, scan_id: &str) -> Result<Vec<Evidence>> {
        let conn = self.conn()?;
        let mut stmt = conn.prepare(
            "SELECT id, scan_id, stage, actor, message, ref_id, created_at
             FROM evidence WHERE scan_id = ? ORDER BY created_at ASC, rowid ASC",
        )?;
        let rows = stmt.query_map(params![scan_id], evidence_from_row)?;
        rows.collect::<std::result::Result<Vec<_>, _>>()
            .map_err(Into::into)
    }
}

const FINDING_SELECT_ONE: &str = "SELECT id, scan_id, rule_id, title, cwe, severity, confidence,
    file_path, line_no, snippet, explanation, risk_score, risk_rationale, reproduced,
    repro_log, validated, false_positive FROM findings WHERE id = ?";

fn scan_from_row(row: &rusqlite::Row) -> rusqlite::Result<Scan> {
    Ok(Scan {
        id: row.get(0)?,
        repo_url: row.get(1)?,
        branch: row.get(2)?,
        status: row.get(3)?,
        created_at: row.get(4)?,
        finished_at: row.get(5)?,
        repo_path: row.get(6)?,
        error: row.get(7)?,
    })
}

fn finding_from_row(row: &rusqlite::Row) -> rusqlite::Result<Finding> {
    Ok(Finding {
        id: row.get(0)?,
        scan_id: row.get(1)?,
        rule_id: row.get(2)?,
        title: row.get(3)?,
        cwe: row.get(4)?,
        severity: row.get(5)?,
        confidence: row.get(6)?,
        file_path: row.get(7)?,
        line_no: row.get(8)?,
        snippet: row.get(9)?,
        explanation: row.get(10)?,
        risk_score: row.get(11)?,
        risk_rationale: row.get(12)?,
        reproduced: row.get(13)?,
        repro_log: row.get(14)?,
        validated: row.get(15)?,
        false_positive: row.get(16)?,
    })
}

fn patch_from_row(row: &rusqlite::Row) -> rusqlite::Result<Patch> {
    Ok(Patch {
        id: row.get(0)?,
        finding_id: row.get(1)?,
        diff: row.get(2)?,
        summary: row.get(3)?,
        applied: row.get(4)?,
        created_at: row.get(5)?,
    })
}

fn verification_from_row(row: &rusqlite::Row) -> rusqlite::Result<Verification> {
    Ok(Verification {
        id: row.get(0)?,
        patch_id: row.get(1)?,
        status: row.get(2)?,
        rescan_clean: row.get(3)?,
        tests_passed: row.get(4)?,
        test_log: row.get(5)?,
        notes: row.get(6)?,
        created_at: row.get(7)?,
    })
}

fn evidence_from_row(row: &rusqlite::Row) -> rusqlite::Result<Evidence> {
    Ok(Evidence {
        id: row.get(0)?,
        scan_id: row.get(1)?,
        stage: row.get(2)?,
        actor: row.get(3)?,
        message: row.get(4)?,
        ref_id: row.get(5)?,
        created_at: row.get(6)?,
    })
}

fn is_constraint_violation(e: &rusqlite::Error) -> bool {
    matches!(
        e,
        rusqlite::Error::SqliteFailure(err, _)
            if err.code == rusqlite::ErrorCode::ConstraintViolation
    )
}
