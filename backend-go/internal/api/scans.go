package api

import (
	"net/http"
	"strings"

	"github.com/patchproof/patchproof-go/internal/pipeline"
)

// createScan handles POST /api/scans.
func (s *Server) createScan(w http.ResponseWriter, r *http.Request) *APIError {
	payload, apiErr := parseJSONBody[ScanCreate](r)
	if apiErr != nil {
		return apiErr
	}
	if err := s.store.InitDB(); err != nil {
		return internalErr(err.Error())
	}
	if payload.RepoURL == nil {
		return unprocessable("invalid JSON: missing field `repo_url`")
	}
	repoURL := strings.TrimSpace(*payload.RepoURL)
	if repoURL == "" {
		return unprocessable("repo_url required")
	}
	if len(repoURL) > 2048 {
		return unprocessable("repo_url too long")
	}
	branch := ""
	if payload.Branch != nil {
		branch = strings.TrimSpace(*payload.Branch)
	}
	if branch == "" {
		branch = "HEAD"
	}
	if len(branch) > 256 {
		return unprocessable("branch too long")
	}
	scan, err := s.store.CreateScan(repoURL, branch)
	if err != nil {
		return internalErr(err.Error())
	}
	s.spawnPipeline(scan.ID)
	out, apiErr := SerializeScan(s.store, scan.ID)
	if apiErr != nil {
		return apiErr
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

// listScans handles GET /api/scans.
func (s *Server) listScans(w http.ResponseWriter, r *http.Request) *APIError {
	if err := s.store.InitDB(); err != nil {
		return internalErr(err.Error())
	}
	scans, err := s.store.ListScans(50)
	if err != nil {
		return internalErr(err.Error())
	}
	out := make([]ScanSummary, 0, len(scans))
	for _, sc := range scans {
		sum, apiErr := SerializeSummary(s.store, sc)
		if apiErr != nil {
			return apiErr
		}
		out = append(out, sum)
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

// getScan handles GET /api/scans/{id}.
func (s *Server) getScan(w http.ResponseWriter, r *http.Request) *APIError {
	out, apiErr := SerializeScan(s.store, r.PathValue("id"))
	if apiErr != nil {
		return apiErr
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

// rerunScan handles POST /api/scans/{id}/rerun.
func (s *Server) rerunScan(w http.ResponseWriter, r *http.Request) *APIError {
	scanID := r.PathValue("id")
	exists, err := s.store.GetScan(scanID)
	if err != nil {
		return internalErr(err.Error())
	}
	if exists == nil {
		return notFound("scan not found")
	}
	// Drop the previous run's results so the new pipeline starts clean;
	// otherwise triage dedupes the new findings against the stale ones.
	if err := s.store.ClearScanResults(scanID); err != nil {
		return internalErr(err.Error())
	}
	if err := s.store.ResetScanQueued(scanID); err != nil {
		return internalErr(err.Error())
	}
	if _, err := s.store.AddEvidence(scanID, "done", "planner", "Scan re-queued for a fresh run", ""); err != nil {
		return internalErr(err.Error())
	}
	s.spawnPipeline(scanID)
	out, apiErr := SerializeScan(s.store, scanID)
	if apiErr != nil {
		return apiErr
	}
	writeJSON(w, http.StatusOK, out)
	return nil
}

func (s *Server) spawnPipeline(scanID string) {
	st := s.store
	settings := s.settings
	go func() {
		pipeline.RunPipeline(st, settings, scanID)
	}()
}
