package api

import (
	"sort"

	"github.com/patchproof/patchproof-go/internal/model"
	"github.com/patchproof/patchproof-go/internal/store"
)

// ScanCreate is the POST /api/scans request body. RepoURL is a pointer so
// a missing field fails validation like serde's required String.
type ScanCreate struct {
	RepoURL *string `json:"repo_url"`
	Branch  *string `json:"branch"`
}

// ImportPayload is the POST /api/github/import request body.
type ImportPayload struct {
	RepoURL *string `json:"repo_url"`
	Branch  *string `json:"branch"`
}

// FileQuery is the GET /api/github/file query string.
type FileQuery struct {
	ScanID string
	Path   string
}

// VerificationOut is one serialized verification.
type VerificationOut struct {
	ID          string `json:"id"`
	Status      string `json:"status"`
	RescanClean bool   `json:"rescan_clean"`
	TestsPassed *bool  `json:"tests_passed"`
	TestLog     string `json:"test_log"`
	Notes       string `json:"notes"`
}

// PatchOut is one serialized patch.
type PatchOut struct {
	ID            string            `json:"id"`
	Diff          string            `json:"diff"`
	Summary       string            `json:"summary"`
	Applied       bool              `json:"applied"`
	Verifications []VerificationOut `json:"verifications"`
}

// FindingOut is one serialized finding.
type FindingOut struct {
	ID            string     `json:"id"`
	RuleID        string     `json:"rule_id"`
	Title         string     `json:"title"`
	CWE           string     `json:"cwe"`
	Severity      string     `json:"severity"`
	Confidence    string     `json:"confidence"`
	FilePath      string     `json:"file_path"`
	LineNo        int64      `json:"line_no"`
	Snippet       string     `json:"snippet"`
	Explanation   string     `json:"explanation"`
	RiskScore     float64    `json:"risk_score"`
	RiskRationale string     `json:"risk_rationale"`
	Reproduced    bool       `json:"reproduced"`
	ReproLog      string     `json:"repro_log"`
	Validated     bool       `json:"validated"`
	FalsePositive bool       `json:"false_positive"`
	Patches       []PatchOut `json:"patches"`
}

// EvidenceOut is one serialized evidence row.
type EvidenceOut struct {
	ID      string `json:"id"`
	Stage   string `json:"stage"`
	Actor   string `json:"actor"`
	Message string `json:"message"`
	RefID   string `json:"ref_id"`
}

// ScanOut is a full scan report.
type ScanOut struct {
	ID         string        `json:"id"`
	RepoURL    string        `json:"repo_url"`
	Branch     string        `json:"branch"`
	Status     string        `json:"status"`
	Error      string        `json:"error"`
	CreatedAt  string        `json:"created_at"`
	FinishedAt *string       `json:"finished_at"`
	Findings   []FindingOut  `json:"findings"`
	Evidence   []EvidenceOut `json:"evidence"`
}

// ScanSummary is a lightweight list entry.
type ScanSummary struct {
	ID            string  `json:"id"`
	RepoURL       string  `json:"repo_url"`
	Branch        string  `json:"branch"`
	Status        string  `json:"status"`
	Error         string  `json:"error"`
	CreatedAt     string  `json:"created_at"`
	FinishedAt    *string `json:"finished_at"`
	FindingCount  int     `json:"finding_count"`
	EvidenceCount int     `json:"evidence_count"`
}

// SerializeScan builds a full scan report: findings sorted by
// (-risk_score, file_path, line_no), evidence by created_at.
func SerializeScan(st *store.Store, scanID string) (ScanOut, *APIError) {
	var out ScanOut
	scan, err := st.GetScan(scanID)
	if err != nil {
		return out, internalErr(err.Error())
	}
	if scan == nil {
		return out, notFound("scan not found")
	}
	findings, err := st.ListFindings(scanID)
	if err != nil {
		return out, internalErr(err.Error())
	}
	sort.SliceStable(findings, func(a, b int) bool {
		if findings[a].RiskScore != findings[b].RiskScore {
			return findings[a].RiskScore > findings[b].RiskScore
		}
		if findings[a].FilePath != findings[b].FilePath {
			return findings[a].FilePath < findings[b].FilePath
		}
		return findings[a].LineNo < findings[b].LineNo
	})
	outFindings := make([]FindingOut, 0, len(findings))
	for _, f := range findings {
		patches, err := st.PatchesForFinding(f.ID)
		if err != nil {
			return out, internalErr(err.Error())
		}
		outPatches := make([]PatchOut, 0, len(patches))
		for _, p := range patches {
			verifications, err := st.VerificationsForPatch(p.ID)
			if err != nil {
				return out, internalErr(err.Error())
			}
			outVerifs := make([]VerificationOut, 0, len(verifications))
			for _, v := range verifications {
				outVerifs = append(outVerifs, VerificationOut{
					ID: v.ID, Status: v.Status, RescanClean: v.RescanClean,
					TestsPassed: v.TestsPassed, TestLog: v.TestLog, Notes: v.Notes,
				})
			}
			outPatches = append(outPatches, PatchOut{
				ID: p.ID, Diff: p.Diff, Summary: p.Summary,
				Applied: p.Applied, Verifications: outVerifs,
			})
		}
		outFindings = append(outFindings, FindingOut{
			ID: f.ID, RuleID: f.RuleID, Title: f.Title, CWE: f.CWE,
			Severity: f.Severity, Confidence: f.Confidence,
			FilePath: f.FilePath, LineNo: f.LineNo, Snippet: f.Snippet,
			Explanation: f.Explanation, RiskScore: f.RiskScore,
			RiskRationale: f.RiskRationale, Reproduced: f.Reproduced,
			ReproLog: f.ReproLog, Validated: f.Validated,
			FalsePositive: f.FalsePositive, Patches: outPatches,
		})
	}
	evidence, err := st.ListEvidence(scanID)
	if err != nil {
		return out, internalErr(err.Error())
	}
	sort.SliceStable(evidence, func(a, b int) bool {
		return evidence[a].CreatedAt < evidence[b].CreatedAt
	})
	outEvidence := make([]EvidenceOut, 0, len(evidence))
	for _, e := range evidence {
		outEvidence = append(outEvidence, EvidenceOut{
			ID: e.ID, Stage: e.Stage, Actor: e.Actor,
			Message: e.Message, RefID: e.RefID,
		})
	}
	return ScanOut{
		ID: scan.ID, RepoURL: scan.RepoURL, Branch: scan.Branch,
		Status: scan.Status, Error: scan.Error, CreatedAt: scan.CreatedAt,
		FinishedAt: scan.FinishedAt, Findings: outFindings, Evidence: outEvidence,
	}, nil
}

// SerializeSummary builds one lightweight list entry (counts only).
func SerializeSummary(st *store.Store, scan model.Scan) (ScanSummary, *APIError) {
	var out ScanSummary
	findingCount, err := st.CountFindings(scan.ID)
	if err != nil {
		return out, internalErr(err.Error())
	}
	evidenceCount, err := st.CountEvidence(scan.ID)
	if err != nil {
		return out, internalErr(err.Error())
	}
	return ScanSummary{
		ID: scan.ID, RepoURL: scan.RepoURL, Branch: scan.Branch,
		Status: scan.Status, Error: scan.Error, CreatedAt: scan.CreatedAt,
		FinishedAt:   scan.FinishedAt,
		FindingCount: findingCount, EvidenceCount: evidenceCount,
	}, nil
}
