package api

import (
	"net/http"
)

// corsMiddleware applies the configured CORS policy: '*' allows any
// origin without credentials; empty emits no CORS headers (deny by
// default); explicit origins are matched with credentials.
func (s *Server) corsMiddleware(next http.Handler) http.Handler {
	origins := s.settings.CORSList()
	wildcard := false
	allowed := make(map[string]bool, len(origins))
	for _, o := range origins {
		if o == "*" {
			wildcard = true
		}
		allowed[o] = true
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		origin := r.Header.Get("Origin")
		if wildcard {
			w.Header().Set("Access-Control-Allow-Origin", "*")
			if r.Method == http.MethodOptions {
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
				if req := r.Header.Get("Access-Control-Request-Headers"); req != "" {
					w.Header().Set("Access-Control-Allow-Headers", req)
				} else {
					w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
				}
				w.WriteHeader(http.StatusNoContent)
				return
			}
			next.ServeHTTP(w, r)
			return
		}
		if len(allowed) == 0 {
			next.ServeHTTP(w, r)
			return
		}
		if origin != "" && allowed[origin] {
			w.Header().Set("Access-Control-Allow-Origin", origin)
			w.Header().Set("Access-Control-Allow-Credentials", "true")
			w.Header().Add("Vary", "Origin")
			if r.Method == http.MethodOptions {
				w.Header().Set("Access-Control-Allow-Methods", "GET, POST, PUT, PATCH, DELETE, OPTIONS")
				w.Header().Set("Access-Control-Allow-Headers", "Content-Type, Authorization")
				w.WriteHeader(http.StatusNoContent)
				return
			}
		}
		next.ServeHTTP(w, r)
	})
}
