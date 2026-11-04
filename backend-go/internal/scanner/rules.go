// Package scanner ports crates/core/src/scanner: line-oriented regex
// detectors for the 7 MVP vulnerability classes plus repo walking.
package scanner

import (
	"regexp"
	"strconv"
	"strings"

	"github.com/patchproof/patchproof-go/internal/model"
)

// RuleMeta holds ordered rule metadata: id, title, CWE, severity.
type RuleMeta struct {
	ID       string
	Title    string
	CWE      string
	Severity string
}

// Rules lists the 7 MVP rules in order.
var Rules = []RuleMeta{
	{"PY-SQLI-001", "Possible SQL injection", "CWE-89", "high"},
	{"PY-CMDI-001", "Possible command injection", "CWE-78", "high"},
	{"PY-XSS-001", "Possible cross-site scripting / unsafe template render", "CWE-79", "medium"},
	{"PY-PATHTRAV-001", "Possible path traversal", "CWE-22", "medium"},
	{"PY-DESER-001", "Insecure deserialization", "CWE-502", "high"},
	{"PY-SECRET-001", "Hardcoded secret", "CWE-798", "medium"},
	{"PY-SSRF-001", "Possible SSRF (unvalidated request URL)", "CWE-918", "medium"},
}

// MetaFor returns the metadata for a rule id, or nil when unknown.
func MetaFor(ruleID string) *RuleMeta {
	for i := range Rules {
		if Rules[i].ID == ruleID {
			return &Rules[i]
		}
	}
	return nil
}

var (
	secretRe               = regexp.MustCompile(`(?i)\b(api[_-]?key|secret|password|passwd|pwd|token|aws_access|aws_secret|private[_-]?key)\b\s*[:=]\s*['"][^'"]{4,}['"]`)
	fstringSQLRe           = regexp.MustCompile(`(?i)\b(SELECT|INSERT|UPDATE|DELETE)\b.*\{`)
	formatSQLRe            = regexp.MustCompile(`(?i)\b(SELECT|INSERT|UPDATE|DELETE)\b.*(\.format\(|%)`)
	executeCallRe          = regexp.MustCompile(`\bexecutemany\s*\(|\bexecutescript\s*\(|\bexecute\s*\(`)
	systemPopenRe          = regexp.MustCompile(`\b(system|popen)\s*\(`)
	shellTrueRe            = regexp.MustCompile(`(?i)\bshell\s*=\s*True\b`)
	subprocessCallRe       = regexp.MustCompile(`\b(Popen|run|call|check_output|check_call|system|popen)\s*\(`)
	evalRe                 = regexp.MustCompile(`\beval\s*\(`)
	execRe                 = regexp.MustCompile(`\bexec\s*\(`)
	execFamilyRe           = regexp.MustCompile(`\b(os\.)?(execl|execle|execlp|execv|execve|execvp|spawnl|spawnlp|spawnv|spawnvp|posix_spawn)\s*\(`)
	renderCallRe           = regexp.MustCompile(`\brender_template_string\s*\(`)
	markupCallRe           = regexp.MustCompile(`\bMarkup\s*\(`)
	openCallRe             = regexp.MustCompile(`\bopen\s*\(`)
	pickleCallRe           = regexp.MustCompile(`\bpickle\s*\.\s*loads?\s*\(`)
	yamlLoadRe             = regexp.MustCompile(`\byaml\s*\.\s*load\s*\(`)
	requestsCallRe         = regexp.MustCompile(`\brequests\s*\.\s*(get|post|put|delete|head|request)\s*\(`)
	requestsFirstArgCallRe = regexp.MustCompile(`\brequests\s*\.\s*\w+\s*\(\s*([A-Za-z_][A-Za-z0-9_]*)\s*\(`)
)

// SanitizerHints mark validator-shaped helpers wrapping a request URL.
var SanitizerHints = []string{"check", "allow", "valid", "sanit", "escape", "clean", "safe"}

// ScanSource scans one Python source file, returning raw findings.
func ScanSource(source string) []model.RawFinding {
	lines := strings.Split(source, "\n")
	// Drop the pseudo-line after a trailing newline so numbering matches
	// Python's splitlines().
	if len(lines) > 0 && lines[len(lines)-1] == "" {
		lines = lines[:len(lines)-1]
	}
	var findings []model.RawFinding
	for idx, line := range lines {
		scanLine(line, idx+1, lines, &findings)
	}
	return dedupe(findings)
}

func scanLine(line string, lineno int, lines []string, out *[]model.RawFinding) {
	if strings.HasPrefix(strings.TrimLeft(line, " \t\r\f\v"), "#") {
		return
	}
	// Match against code only: a trailing `#` comment must never trigger a
	// rule (e.g. `x = 1  # shell=True`).
	code := stripLineComment(line)
	// SQL injection: execute-family with tainted input.
	if executeCallRe.MatchString(code) && isTaintedCallArg(code) {
		*out = append(*out, mk("PY-SQLI-001", lineno, lines,
			"SQL statement built from interpolated input; use parameterized queries.", "high"))
	}
	// Command injection: os.system / os.popen / bare system / popen.
	if systemPopenRe.MatchString(code) {
		*out = append(*out, mk("PY-CMDI-001", lineno, lines,
			"Shell command executed from Python; attacker input may inject commands.", "medium"))
	}
	// Command injection: shell=True on a subprocess-shaped call. A bare
	// `shell=True` with no call on the line (config flag, comment text) is
	// not a sink.
	if shellTrueRe.MatchString(code) &&
		(strings.Contains(code, "subprocess") || subprocessCallRe.MatchString(code)) {
		*out = append(*out, mk("PY-CMDI-001", lineno, lines,
			"subprocess called with shell=True; prefer argv list with shell=False.", "high"))
	}
	// XSS: unescaped template rendering.
	if (renderCallRe.MatchString(code) || markupCallRe.MatchString(code)) &&
		!strings.Contains(code, "escape") {
		*out = append(*out, mk("PY-XSS-001", lineno, lines,
			"Unescaped template/HTML rendering; user input may execute as script.", "medium"))
	}
	// Path traversal: open() with tainted path.
	if openCallRe.MatchString(code) && (isTaintedCallArg(code) || isPathJoinArg(code)) {
		*out = append(*out, mk("PY-PATHTRAV-001", lineno, lines,
			"File opened with an interpolated path; validate and constrain to a base directory.", "medium"))
	}
	// Insecure deserialization: pickle / yaml.load.
	if pickleCallRe.MatchString(code) {
		*out = append(*out, mk("PY-DESER-001", lineno, lines,
			"pickle deserialization of untrusted data can execute arbitrary code.", "high"))
	}
	if yamlLoadRe.MatchString(code) && !strings.Contains(code, "Loader") {
		*out = append(*out, mk("PY-DESER-001", lineno, lines,
			"yaml.load without a safe Loader can execute arbitrary objects.", "high"))
	}
	// Dynamic code execution: eval/exec plus the os.exec/spawn family.
	if evalRe.MatchString(code) || execRe.MatchString(code) {
		*out = append(*out, mk("PY-CMDI-001", lineno, lines,
			"Dynamic code execution via eval/exec on possibly untrusted input.", "high"))
	}
	if execFamilyRe.MatchString(code) {
		*out = append(*out, mk("PY-CMDI-001", lineno, lines,
			"Process execution via os.exec/spawn; attacker input may inject commands.", "medium"))
	}
	// SSRF: requests.* with tainted or variable URL. Fully constant URLs
	// carry no attacker input and are not flagged.
	if requestsCallRe.MatchString(code) {
		if isSanitizerFirstArg(code) {
			// Hardened shape such as requests.get(_checked_url(url)).
		} else if isTaintedCallArg(code) {
			*out = append(*out, mk("PY-SSRF-001", lineno, lines,
				"HTTP request URL built from input; validate against an allowlist.", "medium"))
		} else if !isConstantFirstArg(code) {
			*out = append(*out, mk("PY-SSRF-001", lineno, lines,
				"HTTP request to a variable URL; confirm the host is allowlisted.", "low"))
		}
	}
	// Regex detectors: secrets and SQL keyword + interpolation.
	if secretRe.MatchString(code) {
		*out = append(*out, mk("PY-SECRET-001", lineno, lines,
			"Credential-like value hardcoded in source; move to env/secret store.", "medium"))
	}
	if fstringSQLRe.MatchString(code) || formatSQLRe.MatchString(code) {
		*out = append(*out, mk("PY-SQLI-001", lineno, lines,
			"SQL keyword combined with string interpolation.", "medium"))
	}
}

// isTaintedCallArg is the heuristic taint check: f-string, `.format(`, or
// `%`/`+` formatting applied to a non-constant expression inside the first
// call argument. Pure-constant expressions such as `"a" + "b"` or `100 % 3`
// are not tainted.
func isTaintedCallArg(line string) bool {
	if strings.Contains(line, `f"`) || strings.Contains(line, "f'") ||
		strings.Contains(line, `F"`) || strings.Contains(line, "F'") {
		return true
	}
	if strings.Contains(line, ".format(") {
		return true
	}
	stripped := stripStringLiterals(firstArgRegion(line))
	hasOp := strings.Contains(stripped, "%") || strings.Contains(stripped, "+")
	if !hasOp {
		return false
	}
	for _, c := range stripped {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' {
			return true
		}
	}
	return false
}

// isPathJoinArg catches path-join shapes the generic taint check misses:
// `os.path.join(...)` and `Path(...) / name` compositions.
func isPathJoinArg(line string) bool {
	stripped := stripStringLiterals(firstArgRegion(line))
	if strings.Contains(stripped, "join(") {
		return true
	}
	if !strings.Contains(stripped, "/") {
		return false
	}
	for _, c := range stripped {
		if (c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') || c == '_' {
			return true
		}
	}
	return false
}

// isConstantFirstArg reports whether the first call argument is a plain
// string constant.
func isConstantFirstArg(line string) bool {
	trimmed := strings.TrimLeft(firstArgRegion(line), " \t\r\f\v")
	if trimmed == "" {
		return false
	}
	return trimmed[0] == '"' || trimmed[0] == '\''
}

// stripStringLiterals removes string-literal contents (quote-aware, single
// line) so operator checks only see code.
func stripStringLiterals(region string) string {
	var out strings.Builder
	out.Grow(len(region))
	chars := []rune(region)
	i := 0
	for i < len(chars) {
		c := chars[i]
		if c == '"' || c == '\'' {
			triple := i+2 < len(chars) && chars[i+1] == c && chars[i+2] == c
			if triple {
				i += 3
			} else {
				i++
			}
			for i < len(chars) {
				if triple {
					if i+2 < len(chars) && chars[i] == c && chars[i+1] == c && chars[i+2] == c {
						i += 3
						break
					}
					i++
				} else if chars[i] == '\\' {
					i += 2
				} else if chars[i] == c {
					i++
					break
				} else {
					i++
				}
			}
		} else {
			out.WriteRune(c)
			i++
		}
	}
	return out.String()
}

// stripLineComment cuts a trailing `#` comment, ignoring `#` inside string
// literals.
func stripLineComment(line string) string {
	b := []byte(line)
	var quote byte
	inQuote := false
	i := 0
	for i < len(b) {
		ch := b[i]
		if inQuote {
			if ch == '\\' {
				i += 2
				continue
			}
			if ch == quote {
				inQuote = false
			}
		} else if ch == '"' || ch == '\'' {
			quote = ch
			inQuote = true
		} else if ch == '#' {
			return line[:i]
		}
		i++
	}
	return line
}

// firstArgRegion returns the text between the first `(` and the first
// top-level `,` or closing `)`.
func firstArgRegion(line string) string {
	b := []byte(line)
	open := -1
	for i, ch := range b {
		if ch == '(' {
			open = i
			break
		}
	}
	if open < 0 {
		return ""
	}
	depth := 0
	end := len(line)
loop:
	for i := open; i < len(b); i++ {
		switch b[i] {
		case '(':
			depth++
		case ')':
			depth--
			if depth == 0 {
				end = i
				break loop
			}
		case ',':
			if depth == 1 {
				end = i
				break loop
			}
		}
	}
	start := open + 1
	if start > len(line) {
		start = len(line)
	}
	if end > len(line) {
		end = len(line)
	}
	return line[start:end]
}

// isSanitizerFirstArg reports whether the first argument is a call to a
// validator-shaped helper.
func isSanitizerFirstArg(line string) bool {
	cap := requestsFirstArgCallRe.FindStringSubmatch(line)
	if len(cap) >= 2 {
		lower := strings.ToLower(cap[1])
		for _, h := range SanitizerHints {
			if strings.Contains(lower, h) {
				return true
			}
		}
	}
	return false
}

func mk(ruleID string, lineno int, lines []string, explanation, confidence string) model.RawFinding {
	meta := MetaFor(ruleID)
	return model.RawFinding{
		RuleID:      ruleID,
		Title:       meta.Title,
		CWE:         meta.CWE,
		Severity:    meta.Severity,
		Confidence:  confidence,
		LineNo:      lineno,
		Snippet:     snippet(lines, lineno),
		Explanation: explanation,
	}
}

func snippet(lines []string, lineno int) string {
	start := lineno - 2
	if start < 0 {
		start = 0
	}
	end := lineno + 1
	if end > len(lines) {
		end = len(lines)
	}
	var parts []string
	for i := start; i < end; i++ {
		parts = append(parts, strconv.Itoa(i+1)+": "+lines[i])
	}
	return strings.Join(parts, "\n")
}

func dedupe(findings []model.RawFinding) []model.RawFinding {
	type key struct {
		rule string
		line int
	}
	seen := make(map[key]bool)
	var out []model.RawFinding
	for _, f := range findings {
		k := key{f.RuleID, f.LineNo}
		if !seen[k] {
			seen[k] = true
			out = append(out, f)
		}
	}
	return out
}
