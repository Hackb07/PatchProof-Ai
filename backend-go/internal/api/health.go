package api

import (
	"net/http"
)

// health reports service status (always open, no auth).
func (s *Server) health(w http.ResponseWriter, r *http.Request) *APIError {
	// Effective mock mode: forced on when no API key is configured.
	mock := s.settings.LLMMock || s.settings.MetaAPIKey == ""
	writeJSON(w, http.StatusOK, map[string]any{
		"status":   "ok",
		"app":      s.settings.AppName,
		"llm_mock": mock,
	})
	return nil
}
