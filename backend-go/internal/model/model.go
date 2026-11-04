// Package model ports crates/core/src/model.rs: the data model.
//
// Scan 1-n Finding 1-n Patch 1-n Verification, plus append-only
// Evidence timeline rows.
package model

type Scan struct {
	ID         string
	RepoURL    string
	Branch     string
	Status     string // queued|scanning|triaging|patching|verifying|done|failed
	CreatedAt  string
	FinishedAt *string
	RepoPath   string
	Error      string
}

type Finding struct {
	ID            string
	ScanID        string
	RuleID        string
	Title         string
	CWE           string
	Severity      string
	Confidence    string
	FilePath      string
	LineNo        int64
	Snippet       string
	Explanation   string
	RiskScore     float64
	RiskRationale string
	Reproduced    bool
	ReproLog      string
	Validated     bool
	FalsePositive bool
}

type Patch struct {
	ID        string
	FindingID string
	Diff      string
	Summary   string
	Applied   bool
	CreatedAt string
}

type Verification struct {
	ID          string
	PatchID     string
	Status      string // fixed|unfixed|inconclusive
	RescanClean bool
	TestsPassed *bool
	TestLog     string
	Notes       string
	CreatedAt   string
}

// RawFinding is one unpersisted scanner hit.
type RawFinding struct {
	RuleID      string
	Title       string
	CWE         string
	Severity    string
	Confidence  string
	LineNo      int // 1-based
	Snippet     string
	Explanation string
}

type Evidence struct {
	ID        string
	ScanID    string
	Stage     string // clone|scan|triage|risk|repro|patch|verify|done
	Actor     string
	Message   string
	RefID     string
	CreatedAt string
}
