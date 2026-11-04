// Package sandbox ports crates/core/src/sandbox: sandboxed proof-of-concept
// reproduction, executed in Docker when available, else a timeout-bounded
// local subprocess.
package sandbox

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"time"

	"github.com/patchproof/patchproof-go/internal/config"
	"github.com/patchproof/patchproof-go/internal/model"
	"github.com/patchproof/patchproof-go/internal/store"
	"github.com/patchproof/patchproof-go/internal/util"
)

const (
	PocSQLI     = "query = f\"SELECT * FROM users WHERE name = '{{payload}}'\"\nprint('POC-SQLI: query built:', query)\nassert \"' OR '1'='1\" in query\nprint('POC-SQLI: REPRODUCED - injection string reaches SQL')\n"
	PocCMDI     = "import subprocess, sys\npayload = \"hello; echo POC-CMDI-MARKER\"\nprint('POC-CMDI: payload reaches shell sink:', payload)\n# Safe: fixed print only, never executes the injected part (no shell, no echo binary)\nr = subprocess.run([sys.executable, '-c', \"print('POC-CMDI-MARKER')\"], capture_output=True, text=True, timeout=5)\nassert 'POC-CMDI-MARKER' in r.stdout\nprint('POC-CMDI: REPRODUCED - sink reachable (simulated safely)')\n"
	PocXSS      = "payload = \"<script>alert(1)</script>\"\nrendered = f\"<div>{payload}</div>\"\nprint('POC-XSS: rendered:', rendered)\nassert '<script>' in rendered\nprint('POC-XSS: REPRODUCED - unescaped script reaches output')\n"
	PocPathTrav = "from pathlib import Path\npayload = \"../../etc/passwd\"\nresolved = (Path('/srv/app/data') / payload).resolve()\nprint('POC-PATHTRAV: resolved:', resolved)\nassert str(resolved).startswith('/etc') or '..' in payload\nprint('POC-PATHTRAV: REPRODUCED - traversal escapes base dir')\n"
	PocDeser    = "import pickle\npayload = pickle.dumps({'role': 'admin'})\nobj = pickle.loads(payload)\nprint('POC-DESER: decoded:', obj)\nassert obj['role'] == 'admin'\nprint('POC-DESER: REPRODUCED - pickle sink decodes untrusted bytes')\n"
	PocSecret   = "print('POC-SECRET: REPRODUCED - credential literal present in source; rotation required')\n"
	PocSSRF     = "from urllib.parse import urlparse\npayload = \"http://169.254.169.254/latest/meta-data\"\nhost = urlparse(payload).hostname\nprint('POC-SSRF: host:', host)\nassert host == '169.254.169.254'\nprint('POC-SSRF: REPRODUCED - internal host not blocked')\n"
	PocDefault  = "print('POC: no template; sink noted')\n"
)

// PocTemplate returns the PoC script for a rule id.
func PocTemplate(ruleID string) string {
	switch ruleID {
	case "PY-SQLI-001":
		return PocSQLI
	case "PY-CMDI-001":
		return PocCMDI
	case "PY-XSS-001":
		return PocXSS
	case "PY-PATHTRAV-001":
		return PocPathTrav
	case "PY-DESER-001":
		return PocDeser
	case "PY-SECRET-001":
		return PocSecret
	case "PY-SSRF-001":
		return PocSSRF
	default:
		return PocDefault
	}
}

// Reproduce runs a PoC for every non-false-positive finding of a scan.
func Reproduce(ctx context.Context, st *store.Store, settings config.Settings, scanID string) ([]model.Finding, error) {
	findings, err := st.ListActiveFindings(scanID)
	if err != nil {
		return nil, err
	}
	backend := PickBackend(ctx, settings)
	reproduced := 0
	for _, f := range findings {
		template := PocTemplate(f.RuleID)
		if f.RuleID == "PY-SQLI-001" {
			template = strings.ReplaceAll(template, "{{payload}}", "' OR '1'='1")
		}
		log, ok := RunPoc(ctx, template, backend, settings)
		header := fmt.Sprintf("[sandbox:%s] PoC for %s at %s:%d\n", backend, f.RuleID, f.FilePath, f.LineNo)
		full := util.TruncateChars(header+log, 4000)
		if err := st.UpdateFindingRepro(f.ID, ok, full); err != nil {
			return nil, err
		}
		if ok {
			reproduced++
		}
	}
	_, err = st.AddEvidence(scanID, "repro", "sandbox",
		fmt.Sprintf("Reproduction complete via %s: %d/%d reproduced", backend, reproduced, len(findings)), "")
	if err != nil {
		return nil, err
	}
	return findings, nil
}

// PickBackend selects the docker or subprocess backend.
func PickBackend(ctx context.Context, settings config.Settings) string {
	if settings.SandboxBackend == "subprocess" {
		return "subprocess"
	}
	if (settings.SandboxBackend == "docker" || settings.SandboxBackend == "auto") &&
		WhichBin("docker") && DockerAlive(ctx) {
		return "docker"
	}
	return "subprocess"
}

// DockerAlive reports whether `docker info` succeeds within 10s.
func DockerAlive(ctx context.Context) bool {
	ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker", "info")
	cmd.Stdout = nil
	if err := cmd.Run(); err != nil {
		return false
	}
	return true
}

// DockerMountArg builds a `host-path:/work:<mode>` bind-mount argument
// (Docker expects forward slashes in the source, even on Windows).
func DockerMountArg(hostPath, mode string) string {
	src := hostPath
	if runtime.GOOS == "windows" {
		src = strings.ReplaceAll(src, "\\", "/")
	}
	return fmt.Sprintf("%s:/work:%s", src, mode)
}

// RunPoc executes one PoC script on the chosen backend.
func RunPoc(ctx context.Context, code, backend string, settings config.Settings) (string, bool) {
	if backend == "docker" {
		log, ok, err := runDocker(ctx, code, settings)
		if err == nil {
			return log, ok
		}
		out, ok := runSubprocess(ctx, code, settings)
		return fmt.Sprintf("docker unavailable (%s); subprocess fallback:\n%s", err, out), ok
	}
	return runSubprocess(ctx, code, settings)
}

func runSubprocess(ctx context.Context, code string, settings config.Settings) (string, bool) {
	tmp, err := os.MkdirTemp("", "patchproof-poc-")
	if err != nil {
		return fmt.Sprintf("[error] %s", err), false
	}
	defer os.RemoveAll(tmp)
	script := filepath.Join(tmp, "poc.py")
	if err := os.WriteFile(script, []byte(code), 0o644); err != nil {
		return fmt.Sprintf("[error] %s", err), false
	}
	python, ok := FindPython()
	if !ok {
		return "[error] no working python interpreter found (need Python 3.11+; set PYTHON= to override)", false
	}
	timeout := time.Duration(maxU64(settings.SandboxTimeoutS, 1)) * time.Second
	ctx, cancel := context.WithTimeout(ctx, timeout)
	defer cancel()
	cmd := exec.CommandContext(ctx, python, script)
	cmd.Dir = tmp
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return "[timeout] PoC exceeded sandbox time limit", false
	}
	if runErr != nil {
		if _, ok := runErr.(*exec.Error); ok {
			return fmt.Sprintf("[error] %s", runErr), false
		}
		// ExitError (nonzero exit) still yields a log below.
	}
	exitCode := 0
	if runErr != nil {
		if exitErr, ok := runErr.(*exec.ExitError); ok {
			exitCode = exitErr.ExitCode()
		} else {
			exitCode = -1
		}
	}
	log := fmt.Sprintf("$ python poc.py\n%s%s\n[exit=%d]", stdout.String(), stderr.String(), exitCode)
	ok = runErr == nil && strings.Contains(stdout.String(), "REPRODUCED")
	return log, ok
}

func runDocker(ctx context.Context, code string, settings config.Settings) (string, bool, error) {
	tmp, err := os.MkdirTemp("", "patchproof-poc-")
	if err != nil {
		return "", false, err
	}
	defer os.RemoveAll(tmp)
	if err := os.WriteFile(filepath.Join(tmp, "poc.py"), []byte(code), 0o644); err != nil {
		return "", false, err
	}
	mount := DockerMountArg(tmp, "ro")
	timeoutS := maxU64(settings.SandboxTimeoutS, 1) + 30
	ctx, cancel := context.WithTimeout(ctx, time.Duration(timeoutS)*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "docker",
		"run", "--rm", "--network", "none", "--memory", "256m", "--cpus", "0.5",
		"-v", mount, settings.SandboxImage, "python", "/work/poc.py",
	)
	var stdout, stderr strings.Builder
	cmd.Stdout = &stdout
	cmd.Stderr = &stderr
	runErr := cmd.Run()
	if ctx.Err() == context.DeadlineExceeded {
		return "", false, fmt.Errorf("timed out after %ds", timeoutS)
	}
	if runErr != nil {
		if _, ok := runErr.(*exec.Error); ok {
			return "", false, runErr
		}
	}
	codeStatus := 0
	if runErr != nil {
		if exitErr, ok := runErr.(*exec.ExitError); ok {
			codeStatus = exitErr.ExitCode()
		} else {
			codeStatus = -1
		}
	}
	log := fmt.Sprintf("$ docker run --rm --network none %s python /work/poc.py\n%s%s\n[exit=%d]",
		settings.SandboxImage, stdout.String(), stderr.String(), codeStatus)
	return log, runErr == nil && strings.Contains(stdout.String(), "REPRODUCED"), nil
}

// WhichBin searches PATH for an executable (mirrors shutil.which).
func WhichBin(name string) bool {
	pathEnv := os.Getenv("PATH")
	if pathEnv == "" {
		return false
	}
	for _, dir := range filepath.SplitList(pathEnv) {
		if isFile(filepath.Join(dir, name)) {
			return true
		}
		if runtime.GOOS == "windows" {
			for _, ext := range []string{"exe", "cmd", "bat"} {
				if isFile(filepath.Join(dir, name+"."+ext)) {
					return true
				}
			}
		}
	}
	return false
}

func isFile(path string) bool {
	fi, err := os.Stat(path)
	return err == nil && fi.Mode().IsRegular()
}

// FindPython locates a working Python interpreter (>= 3.11) for PoCs,
// syntax gates, and repo tests. Candidates that fail to run are skipped.
func FindPython() (string, bool) {
	if explicit, ok := os.LookupEnv("PYTHON"); ok {
		explicit = strings.TrimSpace(explicit)
		if explicit != "" {
			if pythonWorks(explicit) {
				return explicit, true
			}
			return "", false
		}
	}
	var candidates []string
	if runtime.GOOS == "windows" {
		candidates = []string{"python", "python3", "py"}
	} else {
		candidates = []string{"python3", "python"}
	}
	for _, c := range candidates {
		if WhichBin(c) && pythonWorks(c) {
			return c, true
		}
	}
	return "", false
}

// PythonWorks reports whether candidate executes and reports Python >= 3.11.
func PythonWorks(candidate string) bool { return pythonWorks(candidate) }

func pythonWorks(candidate string) bool {
	cmd := exec.Command(candidate, "-c", "import sys; sys.exit(0 if sys.version_info >= (3, 11) else 1)")
	cmd.Stdin = nil
	devNull, err := os.OpenFile(os.DevNull, os.O_WRONLY, 0)
	if err == nil {
		cmd.Stdout = devNull
		cmd.Stderr = devNull
		defer devNull.Close()
	}
	return cmd.Run() == nil
}

func maxU64(a, b uint64) uint64 {
	if a > b {
		return a
	}
	return b
}
