package patcher

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/patchproof/patchproof-go/internal/scanner"
)

func fixtureRepo(t *testing.T) string {
	t.Helper()
	// Package dir is backend-go/internal/patcher; the shared workspace
	// fixture lives at the repo root.
	abs, err := filepath.Abs(filepath.Join("..", "..", "..", "fixtures", "vuln-app"))
	if err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(filepath.Join(abs, "app.py")); err != nil {
		t.Fatalf("fixture missing: %s: %s", abs, err)
	}
	return abs
}

func copyDir(t *testing.T, src, dest string) {
	t.Helper()
	if err := os.MkdirAll(dest, 0o755); err != nil {
		t.Fatal(err)
	}
	entries, err := os.ReadDir(src)
	if err != nil {
		t.Fatal(err)
	}
	for _, e := range entries {
		s := filepath.Join(src, e.Name())
		d := filepath.Join(dest, e.Name())
		if e.IsDir() {
			copyDir(t, s, d)
			continue
		}
		data, err := os.ReadFile(s)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(d, data, 0o644); err != nil {
			t.Fatal(err)
		}
	}
}

func writeRepo(t *testing.T, dir, name, content string) string {
	t.Helper()
	repo := filepath.Join(dir, name)
	if err := os.MkdirAll(repo, 0o755); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(repo, "app.py"), []byte(content), 0o644); err != nil {
		t.Fatal(err)
	}
	return repo
}

func TestSequentialPatchesSameCheckoutAllLand(t *testing.T) {
	// Regression test: diffs generated against the original file must all
	// apply to ONE checkout (the verifier's flow), each landing on its own
	// sink even as earlier patches shift line numbers.
	tmp := t.TempDir()
	repo := filepath.Join(tmp, "repo")
	copyDir(t, fixtureRepo(t), repo)
	source, err := os.ReadFile(filepath.Join(repo, "app.py"))
	if err != nil {
		t.Fatal(err)
	}
	raws := scanner.ScanSource(string(source))
	if len(raws) < 7 {
		t.Fatalf("raws: %+v", raws)
	}

	var diffs []string
	for _, raw := range raws {
		diff, _ := DeterministicFix(repo, "app.py", int64(raw.LineNo), raw.RuleID, "hint")
		if diff == "" {
			t.Fatalf("%+v produced an empty diff", raw)
		}
		diffs = append(diffs, diff)
	}
	for i, raw := range raws {
		if !ApplyDiff(repo, diffs[i]) {
			t.Fatalf("%+v failed to apply", raw)
		}
	}
	patched, err := os.ReadFile(filepath.Join(repo, "app.py"))
	if err != nil {
		t.Fatal(err)
	}
	if valid, hasInterp := PythonSyntaxOK(string(patched)); hasInterp && !valid {
		t.Fatalf("patched file has invalid syntax:\n%s", patched)
	}
	if fresh := scanner.ScanSource(string(patched)); len(fresh) != 0 {
		t.Fatalf("sinks still flagged after all patches: %+v", fresh)
	}
}

func TestCMDIMultiwordCommandBecomesArgv(t *testing.T) {
	tmp := t.TempDir()
	repo := writeRepo(t, tmp, "repo", "import subprocess\nsubprocess.run(f\"ls -la {d}\", shell=True)\n")
	diff, _ := DeterministicFix(repo, "app.py", 2, "PY-CMDI-001", "hint")
	if !strings.Contains(diff, "[\"ls\", \"-la\", d]") {
		t.Fatalf("missing argv in diff:\n%s", diff)
	}
	if !strings.Contains(diff, "shell=False") {
		t.Fatalf("missing shell=False in diff:\n%s", diff)
	}
	if !ApplyDiff(repo, diff) {
		t.Fatalf("diff failed to apply:\n%s", diff)
	}
	patched, err := os.ReadFile(filepath.Join(repo, "app.py"))
	if err != nil {
		t.Fatal(err)
	}
	for _, f := range scanner.ScanSource(string(patched)) {
		if f.RuleID == "PY-CMDI-001" {
			t.Fatalf("CMDI still flagged after patch:\n%s", patched)
		}
	}
}

func TestCMDIStringWithoutArgvGetsAdvisoryOnly(t *testing.T) {
	// A bare shell flip on a plain string would break the call; the patcher
	// must not claim a real fix there.
	tmp := t.TempDir()
	repo := writeRepo(t, tmp, "repo", "import subprocess\nsubprocess.run(\"ls -la\", shell=True)\n")
	diff, summary := DeterministicFix(repo, "app.py", 2, "PY-CMDI-001", "hint")
	if !strings.HasPrefix(summary, "Advisory") {
		t.Fatalf("expected advisory summary, got %q\n%s", summary, diff)
	}
}

func TestSQLIDoubleQuotedPlaceholderAndCommentParen(t *testing.T) {
	tmp := t.TempDir()
	repo := writeRepo(t, tmp, "repo", "cursor.execute(f'SELECT * FROM t WHERE a = \"{v}\"')  # foo()\n")
	diff, _ := DeterministicFix(repo, "app.py", 1, "PY-SQLI-001", "hint")
	if !strings.Contains(diff, "= ?', (v,))  # foo()") {
		t.Fatalf("missing param tuple in diff:\n%s", diff)
	}
	if strings.Contains(diff, "\"?\"") {
		t.Fatalf("quoted placeholder leaked into diff:\n%s", diff)
	}
}

func TestFromImportDoesNotSatisfyNeedImport(t *testing.T) {
	tmp := t.TempDir()
	repo := writeRepo(t, tmp, "repo", "from html import escape\nrender_template_string(\"<h1>\" + name + \"</h1>\")\n")
	diff, _ := DeterministicFix(repo, "app.py", 2, "PY-XSS-001", "hint")
	if !strings.Contains(diff, "+import html") {
		t.Fatalf("missing import html in diff:\n%s", diff)
	}
}

func TestPickleLoadFixedLikeLoads(t *testing.T) {
	tmp := t.TempDir()
	repo := writeRepo(t, tmp, "repo", "import pickle\ndata = pickle.load(f)\n")
	diff, _ := DeterministicFix(repo, "app.py", 2, "PY-DESER-001", "hint")
	if !strings.Contains(diff, "json.load(f)") {
		t.Fatalf("missing json.load in diff:\n%s", diff)
	}
}

func TestFixturePatchesApplyAndRescanClean(t *testing.T) {
	tmp := t.TempDir()
	repo := filepath.Join(tmp, "repo")
	copyDir(t, fixtureRepo(t), repo)
	source, err := os.ReadFile(filepath.Join(repo, "app.py"))
	if err != nil {
		t.Fatal(err)
	}
	raws := scanner.ScanSource(string(source))
	if len(raws) < 7 {
		t.Fatalf("raws: %+v", raws)
	}

	// Apply one finding at a time on fresh copies (line numbers stay valid).
	for _, raw := range raws {
		trial := filepath.Join(tmp, fmt.Sprintf("trial-%s-%d", raw.RuleID, raw.LineNo))
		copyDir(t, fixtureRepo(t), trial)
		diff, _ := DeterministicFix(trial, "app.py", int64(raw.LineNo), raw.RuleID, "hint")
		if diff == "" {
			t.Fatalf("%+v produced an empty diff", raw)
		}
		if !ApplyDiff(trial, diff) {
			t.Fatalf("%+v failed to apply", raw)
		}
		patched, err := os.ReadFile(filepath.Join(trial, "app.py"))
		if err != nil {
			t.Fatal(err)
		}
		// Must stay syntactically valid (skipped when no interpreter exists).
		if valid, hasInterp := PythonSyntaxOK(string(patched)); hasInterp && !valid {
			t.Fatalf("%+v broke syntax:\n%s", raw, patched)
		}
		var near []int
		for _, f := range scanner.ScanSource(string(patched)) {
			if f.RuleID != raw.RuleID {
				continue
			}
			d := f.LineNo - raw.LineNo
			if d < 0 {
				d = -d
			}
			if d <= 4 {
				near = append(near, f.LineNo)
			}
		}
		if len(near) != 0 {
			t.Fatalf("%+v still flagged near %v", raw, near)
		}
	}
}
