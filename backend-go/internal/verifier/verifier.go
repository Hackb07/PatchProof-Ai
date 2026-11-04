// Package verifier ports crates/core/src/verifier: fix verification via
// re-scan plus repo tests.
package verifier

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"time"

	"github.com/patchproof/patchproof-go/internal/config"
	"github.com/patchproof/patchproof-go/internal/model"
	"github.com/patchproof/patchproof-go/internal/patcher"
	"github.com/patchproof/patchproof-go/internal/sandbox"
	"github.com/patchproof/patchproof-go/internal/scanner"
	"github.com/patchproof/patchproof-go/internal/store"
	"github.com/patchproof/patchproof-go/internal/util"
)

// VerifyPatches verifies every patch of a scan.
func VerifyPatches(ctx context.Context, st *store.Store, scanID, repoPath string, settings config.Settings) ([]model.Verification, error) {
	findings, err := st.ListFindings(scanID)
	if err != nil {
		return nil, err
	}
	trusted := false
	if scan, err := st.GetScan(scanID); err == nil && scan != nil {
		trusted = config.IsLocalScanRepo(scan.RepoURL)
	}
	var results []model.Verification
	for _, finding := range findings {
		patches, err := st.PatchesForFinding(finding.ID)
		if err != nil {
			return nil, err
		}
		for _, patch := range patches {
			target := filepath.Join(repoPath, finding.FilePath)
			before := readLossyOpt(target)
			applied := false
			if patch.Diff != "" {
				applied = patcher.ApplyDiff(repoPath, patch.Diff)
			}
			if err := st.SetPatchApplied(patch.ID, applied); err != nil {
				return nil, err
			}
			after := readLossyOpt(target)

			rescanClean := RescanClean(before, after, finding)
			testsPassed, testLog := RunRepoTests(ctx, repoPath, trusted, settings)
			status := Decide(applied, rescanClean, testsPassed)
			appliedMsg := "NOT applied"
			if applied {
				appliedMsg = "applied"
			}
			rescanMsg := "still flags the sink"
			if rescanClean {
				rescanMsg = "clean"
			}
			testsMsg := "not found"
			if testsPassed != nil {
				if *testsPassed {
					testsMsg = "passed"
				} else {
					testsMsg = "failed"
				}
			}
			notes := fmt.Sprintf("Patch %s; rescan %s; tests %s.", appliedMsg, rescanMsg, testsMsg)
			verification, err := st.CreateVerification(patch.ID, status, rescanClean, testsPassed,
				util.TruncateChars(testLog, 3000), notes)
			if err != nil {
				return nil, err
			}
			_, err = st.AddEvidence(scanID, "verify", "verifier",
				fmt.Sprintf("Verification %s for patch %s: %s", verification.ID, patch.ID, status),
				verification.ID)
			if err != nil {
				return nil, err
			}
			results = append(results, verification)
		}
	}
	fixed := 0
	for _, v := range results {
		if v.Status == "fixed" {
			fixed++
		}
	}
	_, err = st.AddEvidence(scanID, "verify", "verifier",
		fmt.Sprintf("Verification complete: %d/%d fixed", fixed, len(results)), "")
	if err != nil {
		return nil, err
	}
	return results, nil
}

func readLossyOpt(path string) string {
	bytes, err := os.ReadFile(path)
	if err != nil {
		return ""
	}
	return strings.ToValidUTF8(string(bytes), "\uFFFD")
}

// Decide maps (applied, rescanClean, testsPassed) to a status.
func Decide(applied, rescanClean bool, testsPassed *bool) string {
	if !applied {
		return "unfixed"
	}
	if rescanClean && (testsPassed == nil || *testsPassed) {
		return "fixed"
	}
	if !rescanClean {
		return "unfixed"
	}
	return "inconclusive"
}

// RescanClean re-scans the patched file, anchoring on the fix comment.
func RescanClean(before, after string, finding model.Finding) bool {
	if after == before {
		return false
	}
	// Anchor on the fix comment the patcher always inserts: helper
	// insertions at the top of the file shift the sink away from its
	// original line number, so the original `line_no` window is stale.
	marker := fmt.Sprintf("# PatchProof fix (%s)", finding.RuleID)
	anchor := 0
	for i, l := range strings.Split(after, "\n") {
		if strings.Contains(l, marker) {
			anchor = i + 1
		}
	}
	var fresh []model.RawFinding
	for _, f := range scanner.ScanSource(after) {
		if f.RuleID == finding.RuleID {
			fresh = append(fresh, f)
		}
	}
	beforeCount := 0
	for _, f := range scanner.ScanSource(before) {
		if f.RuleID == finding.RuleID {
			beforeCount++
		}
	}
	if anchor > 0 {
		near := 0
		for _, f := range fresh {
			if absDiff(f.LineNo, anchor) <= 2 {
				near++
			}
		}
		return near == 0 || len(fresh) < beforeCount
	}
	return rescanCleanLegacy(beforeCount, fresh, after, finding)
}

func rescanCleanLegacy(beforeCount int, fresh []model.RawFinding, after string, finding model.Finding) bool {
	markers := []string{
		"# PatchProof fix",
		"shell=False",
		"safe_load",
		"os.environ",
		"html.escape",
		"allowlist",
	}
	lines := strings.Split(after, "\n")
	lineNo := int(finding.LineNo)
	if lineNo < 1 {
		lineNo = 1
	}
	start := lineNo - 3
	if start < 0 {
		start = 0
	}
	end := lineNo + 3
	if end > len(lines) {
		end = len(lines)
	}
	if start > end {
		start = end
	}
	near := strings.Join(lines[start:end], "\n")
	found := false
	for _, m := range markers {
		if strings.Contains(near, m) {
			found = true
			break
		}
	}
	if found {
		sameLine := 0
		for _, f := range fresh {
			if absDiff(f.LineNo, lineNo) <= 2 {
				sameLine++
			}
		}
		return sameLine == 0 || len(fresh) < beforeCount
	}
	return false
}

func absDiff(a, b int) int {
	if a > b {
		return a - b
	}
	return b - a
}

// RunRepoTests runs pytest in the target repo, or explains why not.
func RunRepoTests(ctx context.Context, repoPath string, trustedLocal bool, settings config.Settings) (*bool, string) {
	if !HasPytestFiles(repoPath) {
		return nil, "No pytest-style tests found in target repo."
	}
	// Untrusted (cloned) repos must never execute test code on the host:
	// run them containerized, or skip with a clear message.
	if !trustedLocal {
		if settings.SandboxBackend != "subprocess" &&
			sandbox.WhichBin("docker") && sandbox.DockerAlive(ctx) {
			return runDockerTests(ctx, repoPath, settings)
		}
		return nil, "Test run skipped: remote scan and no Docker sandbox available (refusing to execute untrusted test code on the host)."
	}
	python, ok := sandbox.FindPython()
	if !ok {
		return nil, "Test run failed: no working python interpreter found (need Python 3.11+)"
	}
	ctx, cancel := context.WithTimeout(ctx, 60*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, python, "-m", "pytest", "-q", "-p", "no:cacheprovider")
	cmd.Dir = repoPath
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return nil, "Test run failed: timed out after 60s"
	}
	if runErr != nil {
		if _, ok := runErr.(*exec.Error); ok {
			return nil, fmt.Sprintf("Test run failed: %s", runErr)
		}
	}
	out, errOut := stdout.String(), stderr.String()
	if strings.Contains(out, "No module named pytest") || strings.Contains(errOut, "No module named pytest") {
		return nil, "pytest is not installed for the target interpreter; tests not run."
	}
	code := exitCode(runErr)
	log := fmt.Sprintf("$ pytest -q\n%s%s\n[exit=%d]", out, errOut, code)
	passed := runErr == nil
	return &passed, log
}

func runDockerTests(ctx context.Context, repoPath string, settings config.Settings) (*bool, string) {
	mount := sandbox.DockerMountArg(repoPath, "rw")
	ctx, cancel := context.WithTimeout(ctx, 90*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker",
		"run", "--rm", "--network", "none", "--memory", "256m", "--cpus", "0.5",
		"-v", mount, "-w", "/work", settings.SandboxImage,
		"python", "-m", "pytest", "-q", "-p", "no:cacheprovider",
	)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return nil, "Test run failed: timed out after 90s"
	}
	if runErr != nil {
		if _, ok := runErr.(*exec.Error); ok {
			return nil, fmt.Sprintf("Test run failed: %s", runErr)
		}
	}
	out, errOut := stdout.String(), stderr.String()
	if strings.Contains(out, "No module named pytest") || strings.Contains(errOut, "No module named pytest") {
		return nil, fmt.Sprintf("pytest is not installed in sandbox image %s; tests not run.", settings.SandboxImage)
	}
	if runErr != nil && strings.Contains(errOut, "Unable to find image") {
		return nil, fmt.Sprintf("Sandbox image %s not available locally; tests not run.", settings.SandboxImage)
	}
	code := exitCode(runErr)
	log := fmt.Sprintf("$ docker run --rm --network none %s python -m pytest -q\n%s%s\n[exit=%d]",
		settings.SandboxImage, out, errOut, code)
	passed := runErr == nil
	return &passed, log
}

func exitCode(err error) int {
	if err == nil {
		return 0
	}
	if exitErr, ok := err.(*exec.ExitError); ok {
		return exitErr.ExitCode()
	}
	return -1
}

// HasPytestFiles reports whether test_*.py files exist in root or tests/.
func HasPytestFiles(root string) bool {
	if globPrefix(root, "test_", ".py") {
		return true
	}
	return globPrefix(filepath.Join(root, "tests"), "test_", ".py")
}

func globPrefix(dir, prefix, suffix string) bool {
	entries, err := os.ReadDir(dir)
	if err != nil {
		return false
	}
	for _, e := range entries {
		name := e.Name()
		if strings.HasPrefix(name, prefix) && strings.HasSuffix(name, suffix) && e.Type().IsRegular() {
			return true
		}
	}
	return false
}
