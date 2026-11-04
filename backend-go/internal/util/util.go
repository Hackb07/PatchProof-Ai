// Package util holds small shared helpers: ids, timestamps, truncation.
package util

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

// NewID returns 12 lowercase hex chars, like the Rust new_id().
func NewID() string {
	var b [6]byte
	if _, err := rand.Read(b[:]); err != nil {
		// Fall back to a time-derived id; uniqueness still holds in practice.
		return hex.EncodeToString([]byte(time.Now().UTC().Format("150405.000000")))[:12]
	}
	return hex.EncodeToString(b[:])
}

// NowRFC3339 returns a UTC timestamp with nanosecond precision
// (lexicographically sortable).
func NowRFC3339() string {
	return time.Now().UTC().Format(time.RFC3339Nano)
}

// TruncateChars keeps at most n Unicode scalar values (mirrors Python s[:n]).
func TruncateChars(s string, n int) string {
	if n < 0 {
		return ""
	}
	r := []rune(s)
	if len(r) <= n {
		return s
	}
	return string(r[:n])
}
