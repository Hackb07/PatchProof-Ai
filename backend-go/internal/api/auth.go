package api

import (
	"net/http"
	"strings"
)

// requireAPIKey is the shared-secret auth middleware for the scan
// endpoints (health stays open). Open to all requests unless
// PATCHPROOF_API_KEY is configured.
func (s *Server) requireAPIKey(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		expected := strings.TrimSpace(s.settings.APIKey)
		if expected == "" {
			next.ServeHTTP(w, r)
			return
		}
		byHeader := r.Header.Get("X-Api-Key") == expected
		byBearer := false
		if auth := r.Header.Get("Authorization"); auth != "" {
			if token, ok := strings.CutPrefix(auth, "Bearer "); ok {
				byBearer = strings.TrimSpace(token) == expected
			}
		}
		if byHeader || byBearer {
			next.ServeHTTP(w, r)
			return
		}
		writeError(w, unauthorized("invalid or missing API key"))
	})
}
