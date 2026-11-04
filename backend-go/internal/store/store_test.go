package store

import (
	"path/filepath"
	"testing"

	"github.com/patchproof/patchproof-go/internal/config"
	"github.com/patchproof/patchproof-go/internal/model"
)

func testStore(t *testing.T) *Store {
	t.Helper()
	settings := config.Default()
	settings.DatabaseURL = "sqlite://" + filepath.ToSlash(filepath.Join(t.TempDir(), "test.db"))
	st := FromSettings(settings)
	if err := st.InitDB(); err != nil {
		t.Fatal(err)
	}
	return st
}

func TestResolveDBPath(t *testing.T) {
	if got := resolveDBPath("relative.db"); got != "relative.db" {
		t.Fatalf("got %q", got)
	}
	if got := resolveDBPath("./sub/x.db"); got != "./sub/x.db" {
		t.Fatalf("got %q", got)
	}
	cwd, err := filepath.Abs(".")
	if err != nil {
		t.Fatal(err)
	}
	vol := filepath.VolumeName(cwd)
	if vol == "" {
		t.Skip("no volume name on this platform")
	}
	if got := resolveDBPath("/./patchproof.db"); got != vol+"/./patchproof.db" {
		t.Fatalf("got %q", got)
	}
}

func TestScanLifecycle(t *testing.T) {
	st := testStore(t)
	scan, err := st.CreateScan("https://example.com/r.git", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	if len(scan.ID) != 12 {
		t.Fatalf("id=%q", scan.ID)
	}
	got, err := st.GetScan(scan.ID)
	if err != nil || got == nil || got.Status != "queued" {
		t.Fatalf("got=%+v err=%v", got, err)
	}
	if missing, err := st.GetScan("doesnotexist"); err != nil || missing != nil {
		t.Fatalf("missing=%+v err=%v", missing, err)
	}
	if err := st.UpdateScanStatus(scan.ID, "scanning"); err != nil {
		t.Fatal(err)
	}
	if n, err := st.FailStaleScans(); err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	got, _ = st.GetScan(scan.ID)
	if got.Status != "failed" || got.Error == "" || got.FinishedAt == nil {
		t.Fatalf("got=%+v", got)
	}
	if err := st.ResetScanQueued(scan.ID); err != nil {
		t.Fatal(err)
	}
	got, _ = st.GetScan(scan.ID)
	if got.Status != "queued" || got.FinishedAt != nil {
		t.Fatalf("got=%+v", got)
	}
	if err := st.SetScanDone(scan.ID); err != nil {
		t.Fatal(err)
	}
	if n, err := st.FailStaleScans(); err != nil || n != 0 {
		t.Fatalf("n=%d err=%v", n, err)
	}
}

func TestFindingPatchVerificationEvidence(t *testing.T) {
	st := testStore(t)
	scan, err := st.CreateScan("local", "HEAD")
	if err != nil {
		t.Fatal(err)
	}
	raw := model.RawFinding{RuleID: "PY-SQLI-001", Title: "t", CWE: "CWE-89", Severity: "high", Confidence: "high", LineNo: 3, Snippet: "s", Explanation: "e"}
	f, err := st.CreateFinding(scan.ID, raw, "app.py")
	if err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateFindingRisk(f.ID, 7.5, "r"); err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateFindingRepro(f.ID, true, "log"); err != nil {
		t.Fatal(err)
	}
	if err := st.UpdateFindingValidation(f.ID, true, false); err != nil {
		t.Fatal(err)
	}
	got, err := st.GetFinding(f.ID)
	if err != nil || got == nil || got.RiskScore != 7.5 || !got.Reproduced || !got.Validated {
		t.Fatalf("got=%+v err=%v", got, err)
	}
	p, err := st.CreatePatch(f.ID, "diff", "summary")
	if err != nil {
		t.Fatal(err)
	}
	passed := true
	v, err := st.CreateVerification(p.ID, "fixed", true, &passed, "log", "notes")
	if err != nil {
		t.Fatal(err)
	}
	if v.TestsPassed == nil || !*v.TestsPassed {
		t.Fatalf("v=%+v", v)
	}
	v2, err := st.CreateVerification(p.ID, "inconclusive", false, nil, "", "")
	if err != nil {
		t.Fatal(err)
	}
	if v2.TestsPassed != nil {
		t.Fatalf("v2=%+v", v2)
	}
	if _, err := st.AddEvidence(scan.ID, "scan", "detector", "m", ""); err != nil {
		t.Fatal(err)
	}
	if n, err := st.CountFindings(scan.ID); err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if n, err := st.CountEvidence(scan.ID); err != nil || n != 1 {
		t.Fatalf("n=%d err=%v", n, err)
	}
	if err := st.ClearScanResults(scan.ID); err != nil {
		t.Fatal(err)
	}
	if n, _ := st.CountFindings(scan.ID); n != 0 {
		t.Fatalf("n=%d", n)
	}
	// Evidence is kept as the audit trail.
	if n, _ := st.CountEvidence(scan.ID); n != 1 {
		t.Fatalf("n=%d", n)
	}
}
