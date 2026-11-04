// Package api ports crates/api: the HTTP API built on stdlib net/http.
package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
)

// APIError is a JSON error with the FastAPI {"detail": ...} shape.
type APIError struct {
	Status int
	Detail string
}

func (e *APIError) Error() string { return e.Detail }

func notFound(msg string) *APIError {
	return &APIError{Status: http.StatusNotFound, Detail: msg}
}

func unprocessable(msg string) *APIError {
	return &APIError{Status: http.StatusUnprocessableEntity, Detail: msg}
}

func internalErr(msg string) *APIError {
	return &APIError{Status: http.StatusInternalServerError, Detail: msg}
}

func unauthorized(msg string) *APIError {
	return &APIError{Status: http.StatusUnauthorized, Detail: msg}
}

// writeJSON writes a JSON response with the given status.
func writeJSON(w http.ResponseWriter, status int, v any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(v)
}

// writeError writes an APIError in the {"detail": ...} shape.
func writeError(w http.ResponseWriter, err *APIError) {
	writeJSON(w, err.Status, map[string]string{"detail": err.Detail})
}

// handler adapts a handler returning *APIError into an http.HandlerFunc.
func handler(fn func(w http.ResponseWriter, r *http.Request) *APIError) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if err := fn(w, r); err != nil {
			writeError(w, err)
		}
	}
}

// parseJSONBody parses a JSON request body, reporting errors in the same
// {"detail": ...} shape.
func parseJSONBody[T any](r *http.Request) (T, *APIError) {
	var v T
	body, err := io.ReadAll(io.LimitReader(r.Body, 32<<20))
	if err != nil {
		return v, unprocessable(fmt.Sprintf("invalid JSON: %s", err))
	}
	if err := json.Unmarshal(body, &v); err != nil {
		return v, unprocessable(fmt.Sprintf("invalid JSON: %s", err))
	}
	return v, nil
}
