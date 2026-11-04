package config

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

func TestDefaultRepoRootUsesOSTempDir(t *testing.T) {
	root := DefaultRepoRoot()
	tmp := os.TempDir()
	// Compare volume-insensitive on Windows (temp may be short/long form).
	rel, err := filepath.Rel(tmp, root)
	if err != nil || strings.HasPrefix(rel, "..") {
		t.Fatalf("%q not under %q", root, tmp)
	}
	if !strings.Contains(root, "patchproof") {
		t.Fatalf("%q missing patchproof", root)
	}
	if Default().RepoRoot != root {
		t.Fatalf("default repo root %q != %q", Default().RepoRoot, root)
	}
}

func TestNormalizeLocalPath(t *testing.T) {
	cases := map[string]string{
		"fixtures/vuln-app":               "fixtures/vuln-app",
		"file://fixtures/vuln-app":        "fixtures/vuln-app",
		"/srv/data/repo":                  "/srv/data/repo",
		"C:/src/repo":                     "C:/src/repo",
		"/C:/src/repo":                    "C:/src/repo",
		"file:///C:/src/repo":             "C:/src/repo",
		"  fixtures/vuln-app  ":           "fixtures/vuln-app",
		"file://file://fixtures/vuln-app": "fixtures/vuln-app",
	}
	for in, want := range cases {
		if got := NormalizeLocalPath(in); got != want {
			t.Errorf("NormalizeLocalPath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestParseBool(t *testing.T) {
	for _, s := range []string{"1", "true", "yes", "y", "on", "TRUE", " On "} {
		if !ParseBool(s, false) {
			t.Errorf("ParseBool(%q) = false, want true", s)
		}
	}
	for _, s := range []string{"0", "false", "no", "n", "off", "", "FALSE"} {
		if ParseBool(s, true) {
			t.Errorf("ParseBool(%q) = true, want false", s)
		}
	}
	if !ParseBool("bogus", true) || ParseBool("bogus", false) {
		t.Errorf("ParseBool(bogus) ignored default")
	}
}

func TestDatabasePath(t *testing.T) {
	cases := map[string]string{
		"sqlite:///./patchproof.db": "/./patchproof.db",
		"sqlite:/tmp/x.db?mode=rw":  "/tmp/x.db",
		"sqlite:///C:/data/x.db":    "C:/data/x.db",
		"/C:/data/x.db":             "C:/data/x.db",
		"plain.db":                  "plain.db",
	}
	for in, want := range cases {
		s := Default()
		s.DatabaseURL = in
		if got := s.DatabasePath(); got != want {
			t.Errorf("DatabasePath(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestCORSList(t *testing.T) {
	s := Default()
	s.CORSOrigins = "https://a.example, ,https://b.example "
	got := s.CORSList()
	if len(got) != 2 || got[0] != "https://a.example" || got[1] != "https://b.example" {
		t.Fatalf("CORSList = %q", got)
	}
}
