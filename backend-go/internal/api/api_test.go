package api

import (
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"net/url"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/patchproof/patchproof-go/internal/config"
	"github.com/patchproof/patchproof-go/internal/store"
)

func fixtureRepo(t *testing.T) string {
	t.Helper()
	abs, err := filepath.Abs(filepath.Join("..", "..", "..", "fixtures", "vuln-app"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(abs, "app.py")); err != nil {
		t.Fatalf("fixture missing: %s: %s", abs, err)
	}
	return abs
}

type fixture struct {
	server *Server
	store  *store.Store
}

func testServer(t *testing.T) *fixture {
	t.Helper()
	tmp := t.TempDir()
	db := filepath.Join(tmp, "test.db")
	settings := config.Default()
	settings.DatabaseURL = "sqlite://" + filepath.ToSlash(db)
	settings.RepoRoot = filepath.Join(tmp, "repos")
	settings.LLMMock = true
	st := store.FromSettings(settings)
	if err := st.InitDB(); err != nil {
		t.Fatal(err)
	}
	return &fixture{server: NewServer(st, settings), store: st}
}

func doRequest(t *testing.T, h http.Handler, method, uri, body string, headers map[string]string) (int, map[string]any) {
	t.Helper()
	var reader *strings.Reader
	if body == "" && method == "GET" {
		reader = strings.NewReader("")
	} else {
		reader = strings.NewReader(body)
	}
	req := httptest.NewRequest(method, uri, reader)
	if method == "POST" {
		req.Header.Set("Content-Type", "application/json")
	}
	for k, v := range headers {
		req.Header.Set(k, v)
	}
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	var parsed map[string]any
	if strings.HasPrefix(rec.Header().Get("Content-Type"), "application/json") {
		if err := json.Unmarshal(rec.Body.Bytes(), &parsed); err != nil {
			// Lists decode into any below.
			var arr []any
			if err2 := json.Unmarshal(rec.Body.Bytes(), &arr); err2 != nil {
				t.Fatalf("bad JSON response %q: %s", uri, rec.Body.String())
			}
			parsed = map[string]any{"_array": arr}
		}
	} else if rec.Body.Len() > 0 {
		t.Fatalf("non-JSON response for %s %s: %q", method, uri, rec.Body.String())
	}
	return rec.Code, parsed
}

func getJSON(t *testing.T, h http.Handler, uri string) (int, map[string]any) {
	t.Helper()
	return doRequest(t, h, "GET", uri, "", nil)
}

func postRaw(t *testing.T, h http.Handler, uri, raw string) (int, map[string]any) {
	t.Helper()
	return doRequest(t, h, "POST", uri, raw, nil)
}

func postJSON(t *testing.T, h http.Handler, uri string, body map[string]any) (int, map[string]any) {
	t.Helper()
	raw, _ := json.Marshal(body)
	return postRaw(t, h, uri, string(raw))
}

func waitForDone(t *testing.T, fx *fixture, scanID string) map[string]any {
	t.Helper()
	h := fx.server.Handler()
	deadline := time.Now().Add(180 * time.Second)
	for {
		_, current := getJSON(t, h, "/api/scans/"+scanID)
		status, _ := current["status"].(string)
		if status == "done" || status == "failed" {
			return current
		}
		if time.Now().After(deadline) {
			t.Fatalf("timed out waiting for scan: %v", current)
		}
		time.Sleep(200 * time.Millisecond)
	}
}

func TestHealth(t *testing.T) {
	fx := testServer(t)
	status, body := getJSON(t, fx.server.Handler(), "/api/health")
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%v", status, body)
	}
	if body["status"] != "ok" {
		t.Fatalf("body=%v", body)
	}
}

func TestFixtureScanEndToEnd(t *testing.T) {
	fx := testServer(t)
	h := fx.server.Handler()

	status, body := postJSON(t, h, "/api/scans", map[string]any{"repo_url": fixtureRepo(t)})
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%v", status, body)
	}
	scanID, _ := body["id"].(string)
	if scanID == "" {
		t.Fatalf("missing scan id: %v", body)
	}

	detail := waitForDone(t, fx, scanID)
	if detail["status"] != "done" {
		t.Fatalf("detail=%v", detail)
	}

	findings, err := fx.store.ListFindings(scanID)
	if err != nil {
		t.Fatal(err)
	}
	ruleIDs := map[string]bool{}
	for _, f := range findings {
		ruleIDs[f.RuleID] = true
	}
	for _, expected := range []string{"PY-SQLI-001", "PY-CMDI-001", "PY-DESER-001", "PY-SECRET-001"} {
		if !ruleIDs[expected] {
			t.Errorf("missing rule %s in %v", expected, ruleIDs)
		}
	}
	for _, f := range findings {
		if f.RiskScore <= 0 {
			t.Errorf("finding %s has no risk score", f.ID)
		}
		if f.ReproLog == "" {
			t.Errorf("finding %s has empty repro log", f.ID)
		}
	}

	patches, err := fx.store.ScanPatches(scanID)
	if err != nil {
		t.Fatal(err)
	}
	if len(patches) != len(findings) {
		t.Fatalf("patches=%d findings=%d", len(patches), len(findings))
	}
	for _, p := range patches {
		if p.Diff == "" {
			t.Errorf("patch %s has empty diff", p.ID)
		}
		// Every patch must land on its own sink (content-matched application).
		if !p.Applied {
			t.Errorf("patch %s not applied", p.ID)
		}
	}

	verifs, err := fx.store.ScanVerifications(scanID)
	if err != nil {
		t.Fatal(err)
	}
	if len(verifs) != len(patches) {
		t.Fatalf("verifs=%d patches=%d", len(verifs), len(patches))
	}
	// Every deterministic fix must verify: the rescan is anchored on the
	// fix comment, so helper insertions can't shift it out of the window.
	for _, v := range verifs {
		if v.Status != "fixed" {
			t.Errorf("patch %s: %s (%s)", v.PatchID, v.Status, v.Notes)
		}
	}
}

func TestScanNotFoundAndBadImport(t *testing.T) {
	fx := testServer(t)
	h := fx.server.Handler()

	status, _ := getJSON(t, h, "/api/scans/doesnotexist")
	if status != http.StatusNotFound {
		t.Fatalf("status=%d, want 404", status)
	}

	status, _ = postJSON(t, h, "/api/github/import", map[string]any{"repo_url": ""})
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("status=%d, want 422", status)
	}
}

func TestCreateScanValidation(t *testing.T) {
	fx := testServer(t)
	h := fx.server.Handler()

	// Missing repo_url.
	status, body := postJSON(t, h, "/api/scans", map[string]any{})
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("status=%d body=%v, want 422", status, body)
	}
	if _, ok := body["detail"]; !ok {
		t.Fatalf("missing detail: %v", body)
	}

	// Empty repo_url (same rule as the import endpoint).
	status, _ = postJSON(t, h, "/api/scans", map[string]any{"repo_url": "   "})
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("status=%d, want 422", status)
	}

	// Malformed JSON still yields the {"detail": ...} shape.
	status, body = postRaw(t, h, "/api/scans", "{\"repo_url\":")
	if status != http.StatusUnprocessableEntity {
		t.Fatalf("status=%d body=%v, want 422", status, body)
	}
	if _, ok := body["detail"]; !ok {
		t.Fatalf("missing detail: %v", body)
	}
}

func TestListReturnsSummaries(t *testing.T) {
	fx := testServer(t)
	h := fx.server.Handler()

	status, _ := postJSON(t, h, "/api/scans", map[string]any{"repo_url": fixtureRepo(t)})
	if status != http.StatusOK {
		t.Fatalf("status=%d", status)
	}

	req := httptest.NewRequest("GET", "/api/scans", nil)
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("status=%d", rec.Code)
	}
	var rows []map[string]any
	if err := json.Unmarshal(rec.Body.Bytes(), &rows); err != nil {
		t.Fatal(err)
	}
	if len(rows) != 1 {
		t.Fatalf("rows=%v", rows)
	}
	if _, ok := rows[0]["finding_count"]; !ok {
		t.Fatalf("missing finding_count: %v", rows)
	}
	if _, ok := rows[0]["evidence_count"]; !ok {
		t.Fatalf("missing evidence_count: %v", rows)
	}
	if _, ok := rows[0]["findings"]; ok {
		t.Fatalf("list leaked findings: %v", rows)
	}
	// Let the background pipeline finish so temp cleanup sees no open files.
	scanID, _ := rows[0]["id"].(string)
	waitForDone(t, fx, scanID)
}

func TestRerunStartsClean(t *testing.T) {
	fx := testServer(t)
	h := fx.server.Handler()

	_, body := postJSON(t, h, "/api/scans", map[string]any{"repo_url": fixtureRepo(t)})
	scanID, _ := body["id"].(string)
	first := waitForDone(t, fx, scanID)
	if first["status"] != "done" {
		t.Fatalf("first=%v", first)
	}
	firstFindings, _ := first["findings"].([]any)
	if len(firstFindings) < 7 {
		t.Fatalf("first run found %d findings", len(firstFindings))
	}

	status, _ := postRaw(t, h, fmt.Sprintf("/api/scans/%s/rerun", scanID), "")
	if status != http.StatusOK {
		t.Fatalf("status=%d", status)
	}
	second := waitForDone(t, fx, scanID)
	if second["status"] != "done" {
		t.Fatalf("second=%v", second)
	}
	// No duplication: the rerun cleared the previous results first.
	secondFindings, _ := second["findings"].([]any)
	if len(secondFindings) != len(firstFindings) {
		t.Fatalf("rerun findings=%d, first=%d", len(secondFindings), len(firstFindings))
	}
	patches, err := fx.store.ScanPatches(scanID)
	if err != nil {
		t.Fatal(err)
	}
	if len(patches) != len(firstFindings) {
		t.Fatalf("patches=%d findings=%d", len(patches), len(firstFindings))
	}
}

func TestImportQueuesInBackground(t *testing.T) {
	fx := testServer(t)
	h := fx.server.Handler()

	status, body := postJSON(t, h, "/api/github/import", map[string]any{"repo_url": fixtureRepo(t)})
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%v", status, body)
	}
	// Returns immediately for polling instead of running inline.
	if body["status"] != "queued" {
		t.Fatalf("body=%v", body)
	}
	scanID, _ := body["scan_id"].(string)
	if len(scanID) != 12 {
		t.Fatalf("scan_id=%q", scanID)
	}
	// Let the background pipeline finish so temp cleanup sees no open files.
	if done := waitForDone(t, fx, scanID); done["status"] != "done" {
		t.Fatalf("Detail=%v", done)
	}
}

func TestAPIKeyAuth(t *testing.T) {
	fx := testServer(t)
	settings := fx.server.settings
	settings.APIKey = "secret"
	fx.server = NewServer(fx.store, settings)
	h := fx.server.Handler()

	status, _ := getJSON(t, h, "/api/scans")
	if status != http.StatusUnauthorized {
		t.Fatalf("status=%d, want 401", status)
	}

	status, _ = doRequest(t, h, "GET", "/api/scans", "", map[string]string{"X-Api-Key": "secret"})
	if status != http.StatusOK {
		t.Fatalf("status=%d, want 200", status)
	}

	status, _ = doRequest(t, h, "GET", "/api/scans", "", map[string]string{"Authorization": "Bearer secret"})
	if status != http.StatusOK {
		t.Fatalf("status=%d, want 200 for Bearer", status)
	}

	// Health stays open.
	status, _ = getJSON(t, h, "/api/health")
	if status != http.StatusOK {
		t.Fatalf("status=%d, want 200", status)
	}
}

func TestReadFile(t *testing.T) {
	fx := testServer(t)
	h := fx.server.Handler()

	_, body := postJSON(t, h, "/api/scans", map[string]any{"repo_url": fixtureRepo(t)})
	scanID, _ := body["id"].(string)
	detail := waitForDone(t, fx, scanID)
	if detail["status"] != "done" {
		t.Fatalf("Detail=%v", detail)
	}

	uri := "/api/github/file?scan_id=" + url.QueryEscape(scanID) + "&path=" + url.QueryEscape("app.py")
	status, fileBody := getJSON(t, h, uri)
	if status != http.StatusOK {
		t.Fatalf("status=%d body=%v", status, fileBody)
	}
	content, _ := fileBody["content"].(string)
	if !strings.Contains(content, "render_template_string") {
		t.Fatalf("unexpected file content: %.200s", content)
	}

	// Traversal escapes are rejected.
	bad := "/api/github/file?scan_id=" + url.QueryEscape(scanID) + "&path=" + url.QueryEscape("../../etc/passwd")
	status, _ = getJSON(t, h, bad)
	if status != http.StatusNotFound {
		t.Fatalf("status=%d, want 404", status)
	}

	// Missing scan.
	status, _ = getJSON(t, h, "/api/github/file?scan_id=doesnotexist&path=app.py")
	if status != http.StatusNotFound {
		t.Fatalf("status=%d, want 404", status)
	}
}

func TestCORSHeaders(t *testing.T) {
	fx := testServer(t)
	h := fx.server.Handler()

	req := httptest.NewRequest("GET", "/api/health", nil)
	req.Header.Set("Origin", "http://localhost:5173")
	rec := httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "http://localhost:5173" {
		t.Fatalf("allow-origin=%q", got)
	}

	// Unlisted origins get no CORS headers.
	req = httptest.NewRequest("GET", "/api/health", nil)
	req.Header.Set("Origin", "https://evil.example")
	rec = httptest.NewRecorder()
	h.ServeHTTP(rec, req)
	if got := rec.Header().Get("Access-Control-Allow-Origin"); got != "" {
		t.Fatalf("allow-origin=%q, want empty", got)
	}
}
