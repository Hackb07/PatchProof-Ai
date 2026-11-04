package api

import (
	"net/http"

	"github.com/patchproof/patchproof-go/internal/config"
	"github.com/patchproof/patchproof-go/internal/store"
)

// Server holds shared application state.
type Server struct {
	store    *store.Store
	settings config.Settings
}

// NewServer builds a server with shared state.
func NewServer(st *store.Store, settings config.Settings) *Server {
	return &Server{store: st, settings: settings}
}

// Handler builds the full application router with auth and CORS.
func (s *Server) Handler() http.Handler {
	authed := http.NewServeMux()
	authed.HandleFunc("POST /api/scans", handler(s.createScan))
	authed.HandleFunc("GET /api/scans", handler(s.listScans))
	authed.HandleFunc("GET /api/scans/{id}", handler(s.getScan))
	authed.HandleFunc("POST /api/scans/{id}/rerun", handler(s.rerunScan))
	authed.HandleFunc("POST /api/github/import", handler(s.importRepo))
	authed.HandleFunc("GET /api/github/file", handler(s.readFile))

	mux := http.NewServeMux()
	mux.HandleFunc("GET /api/health", handler(s.health))
	mux.Handle("/api/scans", s.requireAPIKey(authed))
	mux.Handle("/api/scans/", s.requireAPIKey(authed))
	mux.Handle("/api/github/", s.requireAPIKey(authed))

	return s.corsMiddleware(mux)
}
