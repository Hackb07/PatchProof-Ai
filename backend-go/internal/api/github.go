package api

import (
	"io"
	"net/http"
	"os"
	"path/filepath"
	"strings"

	"github.com/patchproof/patchproof-go/internal/pipeline"
	"github.com/patchproof/patchproof-go/internal/util"
)

// MaxFileBytes bounds bytes pulled off disk for the file viewer (decoded
// and truncated to 100k chars afterwards).
const MaxFileBytes = 110_000

// importRepo handles POST /api/github/import.
func (s *Server) importRepo(w http.ResponseWriter, r *http.Request) *APIError {
	payload, apiErr := parseJSONBody[ImportPayload](r)
	if apiErr != nil {
		return apiErr
	}
	if err := s.store.InitDB(); err != nil {
		return internalErr(err.Error())
	}
	url := ""
	if payload.RepoURL != nil {
		url = strings.TrimSpace(*payload.RepoURL)
	}
	if url == "" {
		return unprocessable("repo_url required")
	}
	if len(url) > 2048 {
		return unprocessable("repo_url too long")
	}
	branch := "HEAD"
	if payload.Branch != nil {
		branch = strings.TrimSpace(*payload.Branch)
	}
	if branch == "" {
		branch = "HEAD"
	}
	if len(branch) > 256 {
		return unprocessable("branch too long")
	}
	scan, err := s.store.CreateScan(url, branch)
	if err != nil {
		return internalErr(err.Error())
	}
	// Queue the pipeline in the background and return immediately for
	// polling; awaiting it inline would hang the request for minutes.
	st := s.store
	settings := s.settings
	scanID := scan.ID
	go func() {
		pipeline.RunPipeline(st, settings, scanID)
	}()
	writeJSON(w, http.StatusOK, map[string]string{"scan_id": scan.ID, "status": scan.Status})
	return nil
}

// readFile handles GET /api/github/file.
func (s *Server) readFile(w http.ResponseWriter, r *http.Request) *APIError {
	q := r.URL.Query()
	query := FileQuery{ScanID: q.Get("scan_id"), Path: q.Get("path")}
	scan, err := s.store.GetScan(query.ScanID)
	if err != nil {
		return internalErr(err.Error())
	}
	if scan == nil || scan.RepoPath == "" {
		return notFound("scan or repo not found")
	}
	root := scan.RepoPath
	canonicalRoot, err := filepath.EvalSymlinks(root)
	if err != nil {
		return notFound("file not found")
	}
	// An absolute path escapes the join (Rust Path::join replaces the
	// root); reject it like the failed containment check would.
	if filepath.IsAbs(query.Path) {
		return notFound("file not found")
	}
	target := filepath.Join(root, query.Path)
	canonicalTarget, err := filepath.EvalSymlinks(target)
	if err != nil {
		return notFound("file not found")
	}
	rel, err := filepath.Rel(canonicalRoot, canonicalTarget)
	if err != nil || rel == ".." || strings.HasPrefix(rel, ".."+string(filepath.Separator)) {
		return notFound("file not found")
	}
	fi, err := os.Stat(canonicalTarget)
	if err != nil || !fi.Mode().IsRegular() {
		return notFound("file not found")
	}
	// Bounded read: a huge file in a scanned repo must not OOM the server.
	f, err := os.Open(canonicalTarget)
	if err != nil {
		return notFound("file not found")
	}
	defer f.Close()
	bytes, err := io.ReadAll(io.LimitReader(f, MaxFileBytes))
	if err != nil {
		return notFound("file not found")
	}
	content := strings.ToValidUTF8(string(bytes), "\uFFFD")
	truncated := util.TruncateChars(content, 100_000)
	writeJSON(w, http.StatusOK, map[string]string{
		"scan_id": query.ScanID,
		"path":    query.Path,
		"content": truncated,
	})
	return nil
}
