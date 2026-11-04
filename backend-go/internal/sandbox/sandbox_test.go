package sandbox

import (
	"os"
	"os/exec"
	"strings"
	"testing"
)

func TestPocTemplatesPortable(t *testing.T) {
	// Every template keeps the REPRODUCED marker contract ...
	for _, rule := range []string{
		"PY-SQLI-001",
		"PY-CMDI-001",
		"PY-XSS-001",
		"PY-PATHTRAV-001",
		"PY-DESER-001",
		"PY-SECRET-001",
		"PY-SSRF-001",
	} {
		if !strings.Contains(PocTemplate(rule), "REPRODUCED") {
			t.Errorf("%s template missing REPRODUCED", rule)
		}
	}
	// ... and the CMDI template must not depend on a shell `echo`
	// binary, which does not exist on Windows.
	cmdi := PocTemplate("PY-CMDI-001")
	if !strings.Contains(cmdi, "sys.executable") {
		t.Errorf("CMDI template missing sys.executable:\n%s", cmdi)
	}
	if strings.Contains(cmdi, "shell=True") {
		t.Errorf("CMDI template contains shell=True:\n%s", cmdi)
	}
}

func TestFindPythonReturnsWorkingInterpreter(t *testing.T) {
	// Whatever this machine has (real Python, a broken redirect stub, or
	// nothing), FindPython must only return interpreters that actually run.
	if py, ok := FindPython(); ok {
		cmd := exec.Command(py, "-c", "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)")
		cmd.Stdin = nil
		devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
		if err == nil {
			cmd.Stdout = devNull
			cmd.Stderr = devNull
			defer devNull.Close()
		}
		if err := cmd.Run(); err != nil {
			t.Fatalf("%s failed its own probe: %s", py, err)
		}
	}
}
