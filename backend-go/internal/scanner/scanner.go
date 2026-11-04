// Scan walks a repo checkout and persists findings (ports
// crates/core/src/scanner/scan.rs).
package scanner

import (
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/patchproof/patchproof-go/internal/model"
	"github.com/patchproof/patchproof-go/internal/store"
)

// SkipDirs are vendored directories never scanned.
var SkipDirs = []string{".git", ".venv", "venv", "__pycache__", "node_modules", ".tox"}

// ScanRepo scans every *.py file under repoPath, skipping vendored
// directories.
func ScanRepo(st *store.Store, scanID, repoPath string) ([]model.Finding, error) {
	var files []string
	root := repoPath
	err := filepath.WalkDir(root, func(path string, d fs.DirEntry, err error) error {
		if err != nil {
			return nil
		}
		// Never follow symlinks out of the checkout: a hostile repo
		// could otherwise link evil.py at a host file outside it.
		if d.Type()&fs.ModeSymlink != 0 {
			if d.IsDir() {
				return filepath.SkipDir
			}
			return nil
		}
		if d.IsDir() && path != root {
			name := d.Name()
			for _, skip := range SkipDirs {
				if name == skip {
					return filepath.SkipDir
				}
			}
			return nil
		}
		if !d.IsDir() && filepath.Ext(path) == ".py" {
			files = append(files, path)
		}
		return nil
	})
	if err != nil {
		return nil, err
	}
	sort.Strings(files)

	var created []model.Finding
	for _, path := range files {
		bytes, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		source := strings.ToValidUTF8(string(bytes), "\uFFFD")
		rel, err := filepath.Rel(root, path)
		if err != nil {
			rel = path
		}
		for _, raw := range ScanSource(source) {
			finding, err := st.CreateFinding(scanID, raw, rel)
			if err != nil {
				return nil, err
			}
			created = append(created, finding)
		}
	}
	_, err = st.AddEvidence(scanID, "scan", "detector",
		fmt.Sprintf("Static scan complete: %d raw findings", len(created)), "")
	if err != nil {
		return nil, err
	}
	return created, nil
}
