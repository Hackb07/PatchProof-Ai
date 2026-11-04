// Package pipeline ports crates/core/src/pipeline.rs: the planner agent
// orchestrating scan -> triage -> risk -> repro -> validate -> patch ->
// verify.
package pipeline

import (
	"context"
	"fmt"
	"io/fs"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/patchproof/patchproof-go/internal/agents"
	"github.com/patchproof/patchproof-go/internal/config"
	"github.com/patchproof/patchproof-go/internal/patcher"
	"github.com/patchproof/patchproof-go/internal/sandbox"
	"github.com/patchproof/patchproof-go/internal/scanner"
	"github.com/patchproof/patchproof-go/internal/store"
	"github.com/patchproof/patchproof-go/internal/util"
	"github.com/patchproof/patchproof-go/internal/verifier"
)

// RunPipeline runs the full pipeline for a scan. It never fails outward:
// errors mark the scan `failed` with a truncated message.
func RunPipeline(st *store.Store, settings config.Settings, scanID string) {
	scan, err := st.GetScan(scanID)
	if err != nil {
		_ = st.SetScanFailed(scanID, fmt.Sprintf("database unavailable: %s", err))
		return
	}
	if scan == nil {
		return
	}
	if err := runInner(st, settings, scanID); err != nil {
		msg := err.Error()
		_ = st.SetScanFailed(scanID, util.TruncateChars(msg, 2000))
		_, _ = st.AddEvidence(scanID, "done", "planner", fmt.Sprintf("Pipeline failed: %s", err), "")
	}
}

func runInner(st *store.Store, settings config.Settings, scanID string) error {
	ctx := context.Background()
	if err := st.UpdateScanStatus(scanID, "scanning"); err != nil {
		return err
	}

	repoPath, err := prepareRepo(st, settings, scanID)
	if err != nil {
		return err
	}
	if _, err := scanner.ScanRepo(st, scanID, repoPath); err != nil {
		return err
	}

	if err := st.UpdateScanStatus(scanID, "triaging"); err != nil {
		return err
	}
	llm := agents.NewLlmClient(settings)
	if _, err := agents.Triage(ctx, st, llm, scanID); err != nil {
		return err
	}
	if _, err := agents.Assess(ctx, st, llm, scanID); err != nil {
		return err
	}

	if err := st.UpdateScanStatus(scanID, "patching"); err != nil {
		return err
	}
	if _, err := sandbox.Reproduce(ctx, st, settings, scanID); err != nil {
		return err
	}
	if _, err := agents.Validate(ctx, st, llm, scanID); err != nil {
		return err
	}
	if _, err := patcher.GeneratePatches(st, scanID, repoPath); err != nil {
		return err
	}

	if err := st.UpdateScanStatus(scanID, "verifying"); err != nil {
		return err
	}
	if _, err := verifier.VerifyPatches(ctx, st, scanID, repoPath, settings); err != nil {
		return err
	}

	if err := st.SetScanDone(scanID); err != nil {
		return err
	}
	_, err = st.AddEvidence(scanID, "done", "planner",
		"Pipeline complete: scan, triage, risk, repro, patch, verify", "")
	return err
}

func prepareRepo(st *store.Store, settings config.Settings, scanID string) (string, error) {
	scan, err := st.GetScan(scanID)
	if err != nil {
		return "", err
	}
	if scan == nil {
		return "", store.ErrScanNotFound
	}
	if err := os.MkdirAll(settings.RepoRoot, 0o755); err != nil {
		return "", err
	}
	dest := filepath.Join(settings.RepoRoot, scan.ID)
	url := strings.TrimSpace(scan.RepoURL)
	// Local path support for fixtures/demo: file:// or plain path copies
	// instead of cloning.
	local := config.NormalizeLocalPath(url)
	if fi, err := os.Stat(local); err == nil && fi.IsDir() {
		if _, err := os.Stat(dest); err == nil {
			if err := os.RemoveAll(dest); err != nil {
				return "", err
			}
		}
		if err := copyTree(local, dest); err != nil {
			return "", err
		}
		if err := st.SetScanRepoPath(scanID, dest); err != nil {
			return "", err
		}
		_, err = st.AddEvidence(scanID, "clone", "planner",
			fmt.Sprintf("Local repo copied from %s", local), "")
		if err != nil {
			return "", err
		}
		return dest, nil
	}
	if _, err := os.Stat(dest); err == nil {
		if err := os.RemoveAll(dest); err != nil {
			return "", err
		}
	}
	args := []string{"clone", "--depth", "1"}
	if branch := strings.TrimSpace(scan.Branch); branch != "" && branch != "HEAD" {
		args = append(args, "--branch", branch)
	}
	// `--` keeps a hostile URL/branch from being parsed as git options.
	args = append(args, "--", url, dest)
	ctx, cancel := context.WithTimeout(context.Background(), 120*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "git", args...)
	var stderr strings.Builder
	cmd.Stderr = &stderr
	if err := cmd.Run(); err != nil {
		if ctx.Err() == context.DeadlineExceeded {
			return "", fmt.Errorf("repo error: git clone timed out after 120s")
		}
		if _, ok := err.(*exec.Error); ok {
			return "", fmt.Errorf("repo error: git clone failed: %s", err)
		}
		return "", fmt.Errorf("repo error: git clone failed: %s", strings.TrimSpace(stderr.String()))
	}
	if err := st.SetScanRepoPath(scanID, dest); err != nil {
		return "", err
	}
	_, err = st.AddEvidence(scanID, "clone", "planner",
		fmt.Sprintf("Cloned %s (%s)", url, scan.Branch), "")
	if err != nil {
		return "", err
	}
	return dest, nil
}

// CopyIgnore lists directory names never copied from a local repo.
var CopyIgnore = []string{".git", "__pycache__", ".venv", "venv", "node_modules", ".tox"}

func copyTree(src, dest string) error {
	if err := os.MkdirAll(dest, 0o755); err != nil {
		return err
	}
	return filepath.WalkDir(src, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		// Never copy symlinks: they could point outside the source
		// tree and leak host files into the scan.
		if d.Type()&fs.ModeSymlink != 0 {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		rel, err := filepath.Rel(src, path)
		if err != nil || rel == "." {
			return nil
		}
		// Prune ignored names at any depth (walkdir filter_entry parity).
		for _, part := range strings.FieldsFunc(rel, func(r rune) bool { return r == '/' || r == '\\' }) {
			for _, ignore := range CopyIgnore {
				if part == ignore {
					if d.IsDir() {
						return filepath.SkipDir
					}
					return nil
				}
			}
		}
		target := filepath.Join(dest, rel)
		if d.IsDir() {
			return os.MkdirAll(target, 0o755)
		}
		if !d.Type().IsRegular() {
			return nil
		}
		if err := os.MkdirAll(filepath.Dir(target), 0o755); err != nil {
			return err
		}
		return copyFile(path, target)
	})
}

func copyFile(src, dest string) error {
	data, err := os.ReadFile(src)
	if err != nil {
		return err
	}
	return os.WriteFile(dest, data, 0o644)
}
