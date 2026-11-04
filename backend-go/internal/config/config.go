// Package config ports crates/core/src/config.rs: central settings loaded
// from the environment (after .env loading), plus path helpers.
package config

import (
	"bufio"
	"os"
	"path/filepath"
	"strconv"
	"strings"
)

// Settings mirrors the Rust Settings struct field for field.
type Settings struct {
	AppName         string
	DatabaseURL     string
	RepoRoot        string
	LLMMock         bool
	MetaAPIKey      string
	MetaAPIBase     string
	MetaModel       string
	SandboxBackend  string // auto | docker | subprocess
	SandboxTimeoutS uint64
	SandboxImage    string
	CORSOrigins     string
	APIKey          string
	Host            string
	Port            uint16
}

// Default returns the default settings (demo works offline with LLMMock).
func Default() Settings {
	return Settings{
		AppName:         "PatchProof AI",
		DatabaseURL:     "sqlite:///./patchproof.db",
		RepoRoot:        DefaultRepoRoot(),
		LLMMock:         true,
		MetaAPIKey:      "",
		MetaAPIBase:     "https://api.llama.meta.com/v1",
		MetaModel:       "llama-4-scout",
		SandboxBackend:  "auto",
		SandboxTimeoutS: 20,
		SandboxImage:    "python:3.12-slim",
		CORSOrigins:     "http://localhost:5173,http://127.0.0.1:5173",
		APIKey:          "",
		Host:            "127.0.0.1",
		Port:            8000,
	}
}

// FromEnv loads settings from the environment (after .env loading).
func FromEnv() Settings {
	LoadDotEnv()
	s := Default()
	if v, ok := os.LookupEnv("APP_NAME"); ok {
		s.AppName = v
	}
	if v, ok := os.LookupEnv("DATABASE_URL"); ok {
		s.DatabaseURL = v
	}
	if v, ok := os.LookupEnv("REPO_ROOT"); ok {
		s.RepoRoot = v
	}
	if v, ok := os.LookupEnv("LLM_MOCK"); ok {
		s.LLMMock = ParseBool(v, true)
	}
	if v, ok := os.LookupEnv("META_API_KEY"); ok {
		s.MetaAPIKey = v
	}
	if v, ok := os.LookupEnv("META_API_BASE"); ok {
		s.MetaAPIBase = v
	}
	if v, ok := os.LookupEnv("META_MODEL"); ok {
		s.MetaModel = v
	}
	if v, ok := os.LookupEnv("SANDBOX_BACKEND"); ok {
		s.SandboxBackend = v
	}
	if v, ok := os.LookupEnv("SANDBOX_TIMEOUT_S"); ok {
		if n, err := strconv.ParseUint(strings.TrimSpace(v), 10, 64); err == nil {
			s.SandboxTimeoutS = n
		}
	}
	if v, ok := os.LookupEnv("SANDBOX_IMAGE"); ok {
		if strings.TrimSpace(v) != "" {
			s.SandboxImage = strings.TrimSpace(v)
		}
	}
	if v, ok := os.LookupEnv("CORS_ORIGINS"); ok {
		s.CORSOrigins = v
	}
	if v, ok := os.LookupEnv("PATCHPROOF_API_KEY"); ok {
		s.APIKey = strings.TrimSpace(v)
	}
	if v, ok := os.LookupEnv("HOST"); ok {
		if strings.TrimSpace(v) != "" {
			s.Host = strings.TrimSpace(v)
		}
	}
	if v, ok := os.LookupEnv("PORT"); ok {
		if n, err := strconv.Atoi(strings.TrimSpace(v)); err == nil && n >= 0 && n <= 65535 {
			s.Port = uint16(n)
		}
	}
	return s
}

// DatabasePath derives the SQLite filesystem path from DatabaseURL.
func (s Settings) DatabasePath() string {
	url := strings.TrimSpace(s.DatabaseURL)
	for _, prefix := range []string{"sqlite://", "sqlite:"} {
		if rest, ok := strings.CutPrefix(url, prefix); ok {
			url = rest
			break
		}
	}
	if base, _, ok := strings.Cut(url, "?"); ok {
		url = base
	}
	// Tolerate `/C:/...` style absolute Windows paths.
	if len(url) >= 3 && strings.HasPrefix(url, "/") && url[2] == ':' {
		url = url[1:]
	}
	return url
}

// CORSList returns the comma-separated CORS origins as a trimmed list.
func (s Settings) CORSList() []string {
	var out []string
	for _, o := range strings.Split(s.CORSOrigins, ",") {
		if t := strings.TrimSpace(o); t != "" {
			out = append(out, t)
		}
	}
	return out
}

// DefaultRepoRoot is the default checkout dir inside the OS temp directory.
func DefaultRepoRoot() string {
	return filepath.Join(os.TempDir(), "patchproof", "repos")
}

// NormalizeLocalPath strips file:// prefixes and tolerates /C:/... paths.
func NormalizeLocalPath(raw string) string {
	local := strings.TrimSpace(raw)
	for {
		rest, ok := strings.CutPrefix(local, "file://")
		if !ok {
			break
		}
		local = rest
	}
	if len(local) >= 3 && strings.HasPrefix(local, "/") && local[2] == ':' {
		local = local[1:]
	}
	return local
}

// IsLocalScanRepo reports whether repoURL points at a local directory.
func IsLocalScanRepo(repoURL string) bool {
	fi, err := os.Stat(NormalizeLocalPath(repoURL))
	return err == nil && fi.IsDir()
}

// ParseBool parses 1/true/yes/y/on as true and 0/false/no/n/off/empty as
// false; anything else yields the default.
func ParseBool(raw string, def bool) bool {
	switch strings.ToLower(strings.TrimSpace(raw)) {
	case "1", "true", "yes", "y", "on":
		return true
	case "0", "false", "no", "n", "off", "":
		return false
	default:
		return def
	}
}

// LoadDotEnv loads KEY=VALUE pairs from a .env file in the working
// directory without overriding existing variables (dotenvy parity).
func LoadDotEnv() {
	f, err := os.Open(".env")
	if err != nil {
		return
	}
	defer f.Close()
	sc := bufio.NewScanner(f)
	sc.Buffer(make([]byte, 1024*1024), 1024*1024)
	for sc.Scan() {
		line := strings.TrimSpace(sc.Text())
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		if rest, ok := strings.CutPrefix(line, "export "); ok {
			line = strings.TrimSpace(rest)
		}
		key, val, ok := strings.Cut(line, "=")
		if !ok {
			continue
		}
		key = strings.TrimSpace(key)
		if key == "" {
			continue
		}
		val = strings.TrimSpace(val)
		if len(val) >= 2 {
			if (val[0] == '"' && val[len(val)-1] == '"') ||
				(val[0] == '\'' && val[len(val)-1] == '\'') {
				val = val[1 : len(val)-1]
			}
		}
		if _, exists := os.LookupEnv(key); !exists {
			os.Setenv(key, val)
		}
	}
}
