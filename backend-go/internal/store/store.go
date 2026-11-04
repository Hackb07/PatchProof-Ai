// Package store ports crates/core/src/store.rs: SQLite storage with one
// short-lived connection per operation.
package store

import (
	"database/sql"
	"errors"
	"net/url"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	_ "modernc.org/sqlite"

	"github.com/patchproof/patchproof-go/internal/config"
	"github.com/patchproof/patchproof-go/internal/model"
	"github.com/patchproof/patchproof-go/internal/util"
)

// ErrScanNotFound is returned for operations on a missing scan.
var ErrScanNotFound = errors.New("scan not found")

// Schema is the database DDL, copied verbatim from store.rs.
const Schema = `
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
`

// Store is a SQLite-backed store. Like the Rust version it opens one
// short-lived connection per operation with a busy timeout.
type Store struct {
	dbPath string
}

// New opens a store at dbPath.
func New(dbPath string) *Store {
	return &Store{dbPath: resolveDBPath(dbPath)}
}

// resolveDBPath mirrors how the OS resolves the Rust build's paths: on
// Windows a drive-less rooted path (e.g. "/./patchproof.db" from the
// default sqlite:///./ URL) is relative to the current drive's root.
func resolveDBPath(p string) string {
	if runtime.GOOS != "windows" {
		return p
	}
	if filepath.VolumeName(p) != "" {
		return p
	}
	if !strings.HasPrefix(p, "/") && !strings.HasPrefix(p, "\\") {
		return p
	}
	if cwd, err := os.Getwd(); err == nil {
		if vol := filepath.VolumeName(cwd); vol != "" {
			return vol + p
		}
	}
	return p
}

// FromSettings builds a store from settings.
func FromSettings(s config.Settings) *Store {
	return New(s.DatabasePath())
}

// DBPath returns the filesystem path of the database.
func (s *Store) DBPath() string { return s.dbPath }

func (s *Store) dsn() string {
	p := filepath.ToSlash(s.dbPath)
	// Percent-encode characters that would corrupt the URI filename.
	p = strings.ReplaceAll(p, "?", "%3F")
	p = strings.ReplaceAll(p, "#", "%23")
	var base string
	switch {
	case strings.HasPrefix(p, "/"):
		base = "file://" + p
	case len(p) >= 3 && p[1] == ':' && p[2] == '/':
		base = "file:///" + p
	default:
		u := url.URL{Scheme: "file", Opaque: p}
		base = u.String()
	}
	return base + "?_pragma=busy_timeout%285000%29"
}

func (s *Store) conn() (*sql.DB, error) {
	return sql.Open("sqlite", s.dsn())
}

// InitDB creates parent dirs, applies the schema, and enables WAL mode.
func (s *Store) InitDB() error {
	if dir := filepath.Dir(s.dbPath); dir != "" && dir != "." {
		if err := os.MkdirAll(dir, 0o755); err != nil {
			return err
		}
	}
	db, err := s.conn()
	if err != nil {
		return err
	}
	defer db.Close()
	for _, stmt := range strings.Split(Schema, ";") {
		if strings.TrimSpace(stmt) == "" {
			continue
		}
		if _, err := db.Exec(stmt); err != nil {
			return err
		}
	}
	// Concurrent pipelines + API handlers share this file; WAL keeps
	// readers from blocking writers (with the 5s busy timeout above).
	_, err = db.Exec("PRAGMA journal_mode=WAL;")
	return err
}

// CreateScan inserts a new queued scan, retrying on id collision.
func (s *Store) CreateScan(repoURL, branch string) (model.Scan, error) {
	var lastErr error
	for range 3 {
		scan := model.Scan{
			ID:        util.NewID(),
			RepoURL:   repoURL,
			Branch:    branch,
			Status:    "queued",
			CreatedAt: util.NowRFC3339(),
		}
		db, err := s.conn()
		if err != nil {
			return model.Scan{}, err
		}
		_, err = db.Exec(
			"INSERT INTO scans (id, repo_url, branch, status, created_at, finished_at, repo_path, error) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
			scan.ID, scan.RepoURL, scan.Branch, scan.Status, scan.CreatedAt, nil, "", "",
		)
		db.Close()
		if err == nil {
			return scan, nil
		}
		if isConstraintViolation(err) {
			lastErr = err
			continue
		}
		return model.Scan{}, err
	}
	if lastErr != nil {
		return model.Scan{}, lastErr
	}
	return model.Scan{}, errors.New("scan id collision")
}

// GetScan fetches a scan by id, or nil when missing.
func (s *Store) GetScan(scanID string) (*model.Scan, error) {
	db, err := s.conn()
	if err != nil {
		return nil, err
	}
	defer db.Close()
	row := db.QueryRow(
		"SELECT id, repo_url, branch, status, created_at, finished_at, repo_path, error FROM scans WHERE id = ?",
		scanID,
	)
	var scan model.Scan
	var finished sql.NullString
	err = row.Scan(&scan.ID, &scan.RepoURL, &scan.Branch, &scan.Status, &scan.CreatedAt, &finished, &scan.RepoPath, &scan.Error)
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	if finished.Valid {
		scan.FinishedAt = &finished.String
	}
	return &scan, nil
}

// ListScans returns up to limit scans, newest first.
func (s *Store) ListScans(limit int64) ([]model.Scan, error) {
	db, err := s.conn()
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.Query(
		"SELECT id, repo_url, branch, status, created_at, finished_at, repo_path, error FROM scans ORDER BY created_at DESC, rowid DESC LIMIT ?",
		limit,
	)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Scan
	for rows.Next() {
		var scan model.Scan
		var finished sql.NullString
		if err := rows.Scan(&scan.ID, &scan.RepoURL, &scan.Branch, &scan.Status, &scan.CreatedAt, &finished, &scan.RepoPath, &scan.Error); err != nil {
			return nil, err
		}
		if finished.Valid {
			scan.FinishedAt = &finished.String
		}
		out = append(out, scan)
	}
	return out, rows.Err()
}

func (s *Store) exec(query string, args ...any) error {
	db, err := s.conn()
	if err != nil {
		return err
	}
	defer db.Close()
	_, err = db.Exec(query, args...)
	return err
}

// UpdateScanStatus sets a scan's status.
func (s *Store) UpdateScanStatus(scanID, status string) error {
	return s.exec("UPDATE scans SET status = ? WHERE id = ?", status, scanID)
}

// SetScanRepoPath records a scan's checkout path.
func (s *Store) SetScanRepoPath(scanID, repoPath string) error {
	return s.exec("UPDATE scans SET repo_path = ? WHERE id = ?", repoPath, scanID)
}

// SetScanDone marks a scan done.
func (s *Store) SetScanDone(scanID string) error {
	return s.exec("UPDATE scans SET status = 'done', finished_at = ? WHERE id = ?", util.NowRFC3339(), scanID)
}

// SetScanFailed marks a scan failed with an error message.
func (s *Store) SetScanFailed(scanID, msg string) error {
	return s.exec("UPDATE scans SET status = 'failed', error = ?, finished_at = ? WHERE id = ?", msg, util.NowRFC3339(), scanID)
}

// ResetScanQueued re-queues a scan for a fresh run.
func (s *Store) ResetScanQueued(scanID string) error {
	return s.exec("UPDATE scans SET status = 'queued', error = '', finished_at = NULL WHERE id = ?", scanID)
}

// ClearScanResults deletes a scan's findings, patches, and verifications.
// Evidence rows are kept as the audit trail.
func (s *Store) ClearScanResults(scanID string) error {
	if err := s.exec(
		"DELETE FROM verifications WHERE patch_id IN (SELECT p.id FROM patches p JOIN findings f ON p.finding_id = f.id WHERE f.scan_id = ?)",
		scanID,
	); err != nil {
		return err
	}
	if err := s.exec(
		"DELETE FROM patches WHERE finding_id IN (SELECT id FROM findings WHERE scan_id = ?)",
		scanID,
	); err != nil {
		return err
	}
	return s.exec("DELETE FROM findings WHERE scan_id = ?", scanID)
}

// FailStaleScans marks scans left mid-pipeline by a restart as failed.
func (s *Store) FailStaleScans() (int, error) {
	db, err := s.conn()
	if err != nil {
		return 0, err
	}
	defer db.Close()
	res, err := db.Exec(
		"UPDATE scans SET status = 'failed', error = 'interrupted by server restart', finished_at = ? WHERE status NOT IN ('done', 'failed')",
		util.NowRFC3339(),
	)
	if err != nil {
		return 0, err
	}
	n, err := res.RowsAffected()
	return int(n), err
}

// CreateFinding persists one raw scanner finding.
func (s *Store) CreateFinding(scanID string, raw model.RawFinding, filePath string) (model.Finding, error) {
	f := model.Finding{
		ID:         util.NewID(),
		ScanID:     scanID,
		RuleID:     raw.RuleID,
		Title:      raw.Title,
		CWE:        raw.CWE,
		Severity:   raw.Severity,
		Confidence: raw.Confidence,
		FilePath:   filePath,
		LineNo:     int64(raw.LineNo),
		Snippet:    raw.Snippet,
	}
	db, err := s.conn()
	if err != nil {
		return model.Finding{}, err
	}
	defer db.Close()
	_, err = db.Exec(
		"INSERT INTO findings (id, scan_id, rule_id, title, cwe, severity, confidence, file_path, line_no, snippet, explanation, risk_score, risk_rationale, reproduced, repro_log, validated, false_positive) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)",
		f.ID, f.ScanID, f.RuleID, f.Title, f.CWE, f.Severity, f.Confidence, f.FilePath, f.LineNo, f.Snippet, raw.Explanation, 0.0, "", false, "", false, false,
	)
	if err != nil {
		return model.Finding{}, err
	}
	return f, nil
}

const findingColumns = "id, scan_id, rule_id, title, cwe, severity, confidence, file_path, line_no, snippet, explanation, risk_score, risk_rationale, reproduced, repro_log, validated, false_positive"

func scanFinding(rows interface {
	Scan(...any) error
}) (model.Finding, error) {
	var f model.Finding
	err := rows.Scan(&f.ID, &f.ScanID, &f.RuleID, &f.Title, &f.CWE, &f.Severity, &f.Confidence, &f.FilePath, &f.LineNo, &f.Snippet, &f.Explanation, &f.RiskScore, &f.RiskRationale, &f.Reproduced, &f.ReproLog, &f.Validated, &f.FalsePositive)
	return f, err
}

// GetFinding fetches a finding by id, or nil when missing.
func (s *Store) GetFinding(findingID string) (*model.Finding, error) {
	db, err := s.conn()
	if err != nil {
		return nil, err
	}
	defer db.Close()
	f, err := scanFinding(db.QueryRow("SELECT "+findingColumns+" FROM findings WHERE id = ?", findingID))
	if errors.Is(err, sql.ErrNoRows) {
		return nil, nil
	}
	if err != nil {
		return nil, err
	}
	return &f, nil
}

// ListFindings returns a scan's findings in insertion order.
func (s *Store) ListFindings(scanID string) ([]model.Finding, error) {
	db, err := s.conn()
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.Query("SELECT "+findingColumns+" FROM findings WHERE scan_id = ? ORDER BY rowid", scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Finding
	for rows.Next() {
		f, err := scanFinding(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, f)
	}
	return out, rows.Err()
}

// ListActiveFindings returns a scan's non-false-positive findings.
func (s *Store) ListActiveFindings(scanID string) ([]model.Finding, error) {
	all, err := s.ListFindings(scanID)
	if err != nil {
		return nil, err
	}
	var out []model.Finding
	for _, f := range all {
		if !f.FalsePositive {
			out = append(out, f)
		}
	}
	return out, nil
}

// CountFindings counts a scan's findings.
func (s *Store) CountFindings(scanID string) (int, error) {
	db, err := s.conn()
	if err != nil {
		return 0, err
	}
	defer db.Close()
	var n int64
	if err := db.QueryRow("SELECT COUNT(*) FROM findings WHERE scan_id = ?", scanID).Scan(&n); err != nil {
		return 0, err
	}
	if n < 0 {
		n = 0
	}
	return int(n), nil
}

// CountEvidence counts a scan's evidence rows.
func (s *Store) CountEvidence(scanID string) (int, error) {
	db, err := s.conn()
	if err != nil {
		return 0, err
	}
	defer db.Close()
	var n int64
	if err := db.QueryRow("SELECT COUNT(*) FROM evidence WHERE scan_id = ?", scanID).Scan(&n); err != nil {
		return 0, err
	}
	if n < 0 {
		n = 0
	}
	return int(n), nil
}

// DeleteFinding removes one finding.
func (s *Store) DeleteFinding(findingID string) error {
	return s.exec("DELETE FROM findings WHERE id = ?", findingID)
}

// UpdateFindingRisk records a finding's risk score and rationale.
func (s *Store) UpdateFindingRisk(findingID string, score float64, rationale string) error {
	return s.exec("UPDATE findings SET risk_score = ?, risk_rationale = ? WHERE id = ?", score, rationale, findingID)
}

// UpdateFindingRepro records a finding's reproduction outcome.
func (s *Store) UpdateFindingRepro(findingID string, reproduced bool, log string) error {
	return s.exec("UPDATE findings SET reproduced = ?, repro_log = ? WHERE id = ?", reproduced, log, findingID)
}

// UpdateFindingValidation records a finding's validation outcome.
func (s *Store) UpdateFindingValidation(findingID string, validated, falsePositive bool) error {
	return s.exec("UPDATE findings SET validated = ?, false_positive = ? WHERE id = ?", validated, falsePositive, findingID)
}

// CreatePatch inserts a patch for a finding.
func (s *Store) CreatePatch(findingID, diff, summary string) (model.Patch, error) {
	p := model.Patch{
		ID:        util.NewID(),
		FindingID: findingID,
		Diff:      diff,
		Summary:   summary,
		CreatedAt: util.NowRFC3339(),
	}
	if err := s.exec(
		"INSERT INTO patches (id, finding_id, diff, summary, applied, created_at) VALUES (?, ?, ?, ?, ?, ?)",
		p.ID, p.FindingID, p.Diff, p.Summary, p.Applied, p.CreatedAt,
	); err != nil {
		return model.Patch{}, err
	}
	return p, nil
}

func scanPatch(rows interface {
	Scan(...any) error
}) (model.Patch, error) {
	var p model.Patch
	err := rows.Scan(&p.ID, &p.FindingID, &p.Diff, &p.Summary, &p.Applied, &p.CreatedAt)
	return p, err
}

// PatchesForFinding returns a finding's patches in insertion order.
func (s *Store) PatchesForFinding(findingID string) ([]model.Patch, error) {
	db, err := s.conn()
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.Query("SELECT id, finding_id, diff, summary, applied, created_at FROM patches WHERE finding_id = ? ORDER BY rowid", findingID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Patch
	for rows.Next() {
		p, err := scanPatch(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// ScanPatches returns all patches of a scan in insertion order.
func (s *Store) ScanPatches(scanID string) ([]model.Patch, error) {
	db, err := s.conn()
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.Query("SELECT p.id, p.finding_id, p.diff, p.summary, p.applied, p.created_at FROM patches p JOIN findings f ON p.finding_id = f.id WHERE f.scan_id = ? ORDER BY p.rowid", scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Patch
	for rows.Next() {
		p, err := scanPatch(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, p)
	}
	return out, rows.Err()
}

// SetPatchApplied records whether a patch applied cleanly.
func (s *Store) SetPatchApplied(patchID string, applied bool) error {
	return s.exec("UPDATE patches SET applied = ? WHERE id = ?", applied, patchID)
}

// CreateVerification inserts a verification row for a patch.
func (s *Store) CreateVerification(patchID, status string, rescanClean bool, testsPassed *bool, testLog, notes string) (model.Verification, error) {
	v := model.Verification{
		ID:          util.NewID(),
		PatchID:     patchID,
		Status:      status,
		RescanClean: rescanClean,
		TestsPassed: testsPassed,
		TestLog:     testLog,
		Notes:       notes,
		CreatedAt:   util.NowRFC3339(),
	}
	var tp sql.NullBool
	if testsPassed != nil {
		tp = sql.NullBool{Bool: *testsPassed, Valid: true}
	}
	if err := s.exec(
		"INSERT INTO verifications (id, patch_id, status, rescan_clean, tests_passed, test_log, notes, created_at) VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
		v.ID, v.PatchID, v.Status, v.RescanClean, tp, v.TestLog, v.Notes, v.CreatedAt,
	); err != nil {
		return model.Verification{}, err
	}
	return v, nil
}

func scanVerification(rows interface {
	Scan(...any) error
}) (model.Verification, error) {
	var v model.Verification
	var tp sql.NullBool
	err := rows.Scan(&v.ID, &v.PatchID, &v.Status, &v.RescanClean, &tp, &v.TestLog, &v.Notes, &v.CreatedAt)
	if err != nil {
		return model.Verification{}, err
	}
	if tp.Valid {
		v.TestsPassed = &tp.Bool
	}
	return v, nil
}

// VerificationsForPatch returns a patch's verifications in insertion order.
func (s *Store) VerificationsForPatch(patchID string) ([]model.Verification, error) {
	db, err := s.conn()
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.Query("SELECT id, patch_id, status, rescan_clean, tests_passed, test_log, notes, created_at FROM verifications WHERE patch_id = ? ORDER BY rowid", patchID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Verification
	for rows.Next() {
		v, err := scanVerification(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// ScanVerifications returns all verifications of a scan in insertion order.
func (s *Store) ScanVerifications(scanID string) ([]model.Verification, error) {
	db, err := s.conn()
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.Query("SELECT v.id, v.patch_id, v.status, v.rescan_clean, v.tests_passed, v.test_log, v.notes, v.created_at FROM verifications v JOIN patches p ON v.patch_id = p.id JOIN findings f ON p.finding_id = f.id WHERE f.scan_id = ? ORDER BY v.rowid", scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Verification
	for rows.Next() {
		v, err := scanVerification(rows)
		if err != nil {
			return nil, err
		}
		out = append(out, v)
	}
	return out, rows.Err()
}

// AddEvidence appends one timeline row.
func (s *Store) AddEvidence(scanID, stage, actor, message, refID string) (model.Evidence, error) {
	e := model.Evidence{
		ID:        util.NewID(),
		ScanID:    scanID,
		Stage:     stage,
		Actor:     actor,
		Message:   message,
		RefID:     refID,
		CreatedAt: util.NowRFC3339(),
	}
	if err := s.exec(
		"INSERT INTO evidence (id, scan_id, stage, actor, message, ref_id, created_at) VALUES (?, ?, ?, ?, ?, ?, ?)",
		e.ID, e.ScanID, e.Stage, e.Actor, e.Message, e.RefID, e.CreatedAt,
	); err != nil {
		return model.Evidence{}, err
	}
	return e, nil
}

// ListEvidence returns a scan's timeline oldest first.
func (s *Store) ListEvidence(scanID string) ([]model.Evidence, error) {
	db, err := s.conn()
	if err != nil {
		return nil, err
	}
	defer db.Close()
	rows, err := db.Query("SELECT id, scan_id, stage, actor, message, ref_id, created_at FROM evidence WHERE scan_id = ? ORDER BY created_at ASC, rowid ASC", scanID)
	if err != nil {
		return nil, err
	}
	defer rows.Close()
	var out []model.Evidence
	for rows.Next() {
		var e model.Evidence
		if err := rows.Scan(&e.ID, &e.ScanID, &e.Stage, &e.Actor, &e.Message, &e.RefID, &e.CreatedAt); err != nil {
			return nil, err
		}
		out = append(out, e)
	}
	return out, rows.Err()
}

func isConstraintViolation(err error) bool {
	return err != nil && strings.Contains(err.Error(), "UNIQUE constraint failed")
}
