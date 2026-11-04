// Package patcher ports crates/core/src/patcher: deterministic per-rule
// patch generation plus unified-diff application.
package patcher

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strings"

	"github.com/patchproof/patchproof-go/internal/model"
	"github.com/patchproof/patchproof-go/internal/sandbox"
	"github.com/patchproof/patchproof-go/internal/store"
)

// FixHint returns the per-rule fix guidance string.
func FixHint(ruleID string) string {
	switch ruleID {
	case "PY-SQLI-001":
		return "Use a parameterized query: cursor.execute('SELECT ... WHERE name = ?', (name,)) \u2014 never interpolate."
	case "PY-CMDI-001":
		return "Use subprocess.run([...], shell=False) with an argv list; never shell=True with input."
	case "PY-XSS-001":
		return "Escape output with html.escape() or use autoescaped templates; avoid render_template_string with input."
	case "PY-PATHTRAV-001":
		return "Resolve against a base dir and reject paths escaping it via _confined_path()."
	case "PY-DESER-001":
		return "Replace pickle/yaml.load with json.loads, or yaml.safe_load with an explicit Loader."
	case "PY-SECRET-001":
		return "Load from environment: os.environ['SECRET'] \u2014 remove the literal and rotate it."
	case "PY-SSRF-001":
		return "Validate the URL host against an allowlist via _checked_url() before requesting."
	default:
		return "Apply the minimal safe fix."
	}
}

// ConfinedHelper is the path-confinement helper injected for PATHTRAV fixes.
const ConfinedHelper = `from pathlib import Path as _PPPath


def _confined_path(base, name):
    """Join *name* onto *base*, rejecting escapes (PatchProof fix)."""
    root = _PPPath(base).resolve()
    p = (root / name).resolve()
    try:
        p.relative_to(root)
    except ValueError:
        raise ValueError("path escapes base directory")
    return str(p)


`

// CheckedURLHelper is the URL guard injected for SSRF fixes.
const CheckedURLHelper = `import ipaddress as _pp_ip
from urllib.parse import urlparse as _pp_urlparse


def _checked_url(url):
    """Reject non-allowlisted/internal hosts (PatchProof fix).

    Denylist guard: sensitive callers should use a strict allowlist of
    expected hosts instead.
    """
    host = (_pp_urlparse(url).hostname or "").lower().rstrip(".")
    if not host or host.isdigit():
        raise ValueError("URL host is not allowlisted")
    if host == "localhost" or host.endswith((".localhost", ".internal", ".local", ".lan")):
        raise ValueError("URL host is not allowlisted")
    try:
        ip = _pp_ip.ip_address(host)
    except ValueError:
        pass
    else:
        if ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified:
            raise ValueError("URL host is not allowlisted")
    return url


`

var (
	secretAssignRe   = regexp.MustCompile(`^(\s*)([A-Za-z_][A-Za-z0-9_]*)\s*=\s*("[^"\n]*"|'[^'\n]*')\s*(#.*)?$`)
	sqliExecRe       = regexp.MustCompile(`(\.execute(?:many|script)?\(\s*)f(["'])`)
	cmdiRunRe        = regexp.MustCompile(`(subprocess\.\w+\(\s*)f(["'])(.*?)\{([^{}]+)\}(.*?)["']`)
	subprocessListRe = regexp.MustCompile(`subprocess\.\w+\(\s*\[`)
	interpVarRe      = regexp.MustCompile(`\{([^{}]+)\}`)
	identRe          = regexp.MustCompile(`^[A-Za-z_][A-Za-z0-9_]*$`)
	xssMidRe         = regexp.MustCompile(`\+\s*([A-Za-z_][A-Za-z0-9_]*)\s*\+`)
	xssEndRe         = regexp.MustCompile(`\+\s*([A-Za-z_][A-Za-z0-9_]*)\s*\)`)
	pathtravOpenRe   = regexp.MustCompile(`open\(\s*f"([^"{}\n]*)/\{([^{}]+)\}"\s*\)`)
	ssrfReqRe        = regexp.MustCompile(`(requests\.(?:get|post|put|delete|head|request)\(\s*)f"\{([^{}]+)\}"`)
)

// GeneratePatches creates one patch per non-false-positive finding.
func GeneratePatches(st *store.Store, scanID, repoPath string) ([]model.Patch, error) {
	findings, err := st.ListActiveFindings(scanID)
	if err != nil {
		return nil, err
	}
	var patches []model.Patch
	for _, f := range findings {
		hint := FixHint(f.RuleID)
		diff, summary := DeterministicFix(repoPath, f.FilePath, f.LineNo, f.RuleID, hint)
		patch, err := st.CreatePatch(f.ID, diff, summary)
		if err != nil {
			return nil, err
		}
		_, err = st.AddEvidence(scanID, "patch", "patcher",
			fmt.Sprintf("Patch %s for %s at %s:%d", patch.ID, f.RuleID, f.FilePath, f.LineNo), patch.ID)
		if err != nil {
			return nil, err
		}
		patches = append(patches, patch)
	}
	_, err = st.AddEvidence(scanID, "patch", "patcher",
		fmt.Sprintf("Patch generation complete: %d patches", len(patches)), "")
	if err != nil {
		return nil, err
	}
	return patches, nil
}

// DeterministicFix computes a file transform plus unified diff for one sink.
func DeterministicFix(repoPath, filePath string, lineNo int64, ruleID, hint string) (string, string) {
	target := filepath.Join(repoPath, filePath)
	bytes, err := os.ReadFile(target)
	if err != nil {
		return "", "Target file unreadable; manual fix required."
	}
	content := strings.ToValidUTF8(string(bytes), "\uFFFD")
	original := splitKeepEnds(content)
	if len(original) == 0 {
		return "", "Target file empty; manual fix required."
	}
	if fixed, topPos, topLen, sinkIdx, ok := applyRealFix(original, lineNo, ruleID); ok {
		summary := fmt.Sprintf("Minimal fix for %s at line %d: %s", ruleID, lineNo, hint)
		return structuredDiff(original, fixed, topPos, topLen, sinkIdx, filePath), summary
	}
	summary := fmt.Sprintf("Advisory patch for %s at line %d: %s", ruleID, lineNo, hint)
	fixed, topPos, topLen, sinkIdx := advisoryFix(original, lineNo, ruleID)
	return structuredDiff(original, fixed, topPos, topLen, sinkIdx, filePath), summary
}

func splitKeepEnds(s string) []string {
	if s == "" {
		return nil
	}
	var out []string
	start := 0
	for i := 0; i < len(s); i++ {
		if s[i] == '\n' {
			out = append(out, s[start:i+1])
			start = i + 1
		}
	}
	if start < len(s) {
		out = append(out, s[start:])
	}
	return out
}

// applyRealFix attempts a real fix, returning the fixed lines plus layout:
// fixed = original[..topPos] + topBlock + original[topPos..] with the sink
// line replaced.
func applyRealFix(original []string, lineNo int64, ruleID string) (fixed []string, topPos, topLen, sinkIdx int, ok bool) {
	idx0 := int(minI64(maxI64(lineNo-1, 0), int64(len(original)-1)))
	line := original[idx0]
	source := strings.Join(original, "")
	var topBlock []string
	var newSink string
	var fixedOK bool
	switch ruleID {
	case "PY-SQLI-001":
		topBlock, newSink, fixedOK = fixSQLi(line)
	case "PY-CMDI-001":
		topBlock, newSink, fixedOK = fixCMDi(line)
	case "PY-XSS-001":
		topBlock, newSink, fixedOK = fixXSS(source, line)
	case "PY-PATHTRAV-001":
		topBlock, newSink, fixedOK = fixPathTrav(source, line)
	case "PY-DESER-001":
		topBlock, newSink, fixedOK = fixDeser(source, line)
	case "PY-SECRET-001":
		topBlock, newSink, fixedOK = fixSecret(source, line)
	case "PY-SSRF-001":
		topBlock, newSink, fixedOK = fixSSRF(source, line)
	default:
		return nil, 0, 0, 0, false
	}
	if !fixedOK {
		return nil, 0, 0, 0, false
	}
	if newSink == line && len(topBlock) == 0 {
		return nil, 0, 0, 0, false
	}
	topPos = insertPos(original)
	if topPos > len(original) {
		topPos = len(original)
	}
	newLines := make([]string, 0, len(original)+len(topBlock)+1)
	newLines = append(newLines, original[:topPos]...)
	newLines = append(newLines, topBlock...)
	newLines = append(newLines, original[topPos:]...)
	idx := idx0 + len(topBlock)
	newLines[idx] = newSink
	indent := leadingWhitespace(line)
	hint := FixHint(ruleID)
	comment := fmt.Sprintf("%s# PatchProof fix (%s): %s\n", indent, ruleID, hint)
	newLines = append(newLines, "")
	copy(newLines[idx+1:], newLines[idx:])
	newLines[idx] = comment
	topLen = len(topBlock)
	if valid, hasInterp := PythonSyntaxOK(strings.Join(newLines, "")); hasInterp {
		if !valid {
			return nil, 0, 0, 0, false
		}
		return newLines, topPos, topLen, idx0, true
	} else if !BracketsBalanced(strings.Join(newLines, "")) {
		return nil, 0, 0, 0, false
	}
	return newLines, topPos, topLen, idx0, true
}

func advisoryFix(original []string, lineNo int64, ruleID string) (fixed []string, topPos, topLen, sinkIdx int) {
	idx := int(minI64(maxI64(lineNo-1, 0), int64(len(original)-1)))
	indent := leadingWhitespace(original[idx])
	hint := FixHint(ruleID)
	fixed = append([]string(nil), original...)
	comment := fmt.Sprintf("%s# PatchProof fix (%s): %s\n", indent, ruleID, hint)
	fixed = append(fixed, "")
	copy(fixed[idx+1:], fixed[idx:])
	fixed[idx] = comment
	return fixed, 0, 0, idx
}

func leadingWhitespace(line string) string {
	i := 0
	for i < len(line) {
		c := line[i]
		if c == ' ' || c == '\t' || c == '\n' || c == '\r' || c == '\f' || c == '\v' {
			i++
			continue
		}
		break
	}
	return line[:i]
}

// insertPos finds where helpers/imports go: after the shebang, encoding
// cookie, module docstring, and `from __future__` imports.
func insertPos(lines []string) int {
	idx := 0
	if len(lines) > 0 && strings.HasPrefix(lines[0], "#!") {
		idx = 1
	}
	taken := 0
	for i := idx; i < len(lines) && taken < 2; i++ {
		if strings.Contains(lines[i], "coding:") || strings.Contains(lines[i], "coding=") {
			idx = i + 1
			break
		}
		taken++
	}
	i := idx
	for i < len(lines) {
		stripped := strings.TrimSpace(lines[i])
		if stripped == "" || strings.HasPrefix(stripped, "#") {
			i++
			continue
		}
		break
	}
	for _, quote := range []string{"\"\"\"", "'''"} {
		if i < len(lines) && strings.HasPrefix(strings.TrimLeft(lines[i], " \t"), quote) {
			rest := strings.TrimLeft(lines[i], " \t")[len(quote):]
			if strings.Contains(rest, quote) {
				idx = i + 1
			} else {
				for j := i + 1; j < len(lines); j++ {
					if strings.Contains(lines[j], quote) {
						idx = j + 1
						break
					}
				}
			}
			i = idx
			break
		}
	}
	j := i
	for j < len(lines) {
		stripped := strings.TrimSpace(lines[j])
		if stripped == "" {
			j++
			continue
		}
		if strings.HasPrefix(stripped, "from __future__ import ") {
			idx = j + 1
			j++
			continue
		}
		break
	}
	if idx > len(lines) {
		idx = len(lines)
	}
	return idx
}

func needImport(source, module, stmt string) []string {
	// Only `import <module>` (without `as`) binds the plain module name;
	// `from <module> import ...` and `import <module> as ...` do not.
	for _, line := range strings.Split(source, "\n") {
		if rest, ok := strings.CutPrefix(strings.TrimLeft(line, " \t"), "import "); ok {
			list := rest
			if h, _, ok := strings.Cut(list, "#"); ok {
				list = h
			}
			for _, part := range strings.Split(list, ",") {
				part = strings.TrimSpace(part)
				if part == module || strings.HasPrefix(part, module+".") {
					return nil
				}
			}
		}
	}
	return []string{stmt + "\n"}
}

func fixSQLi(line string) ([]string, string, bool) {
	if strings.Count(line, "{") != 1 || !strings.Contains(line, "}") {
		return nil, "", false
	}
	loc := sqliExecRe.FindStringSubmatchIndex(line)
	if loc == nil {
		return nil, "", false
	}
	mStart, mEnd := loc[0], loc[1]
	if strings.Contains(line[mEnd:], ", (") {
		return nil, "", false
	}
	g1 := line[loc[2]:loc[3]]
	g2 := line[loc[4]:loc[5]]
	varCap := interpVarRe.FindStringSubmatch(line)
	if len(varCap) < 2 {
		return nil, "", false
	}
	expr := strings.TrimSpace(varCap[1])
	if !identRe.MatchString(expr) {
		return nil, "", false
	}
	body := line[:mStart] + g1 + g2 + line[mEnd:]
	single := "'{" + expr + "}'"
	double := "\"{" + expr + "}\""
	if strings.Contains(body, single) {
		body = strings.Replace(body, single, "?", 1)
	} else if strings.Contains(body, double) {
		body = strings.Replace(body, double, "?", 1)
	} else {
		body = strings.Replace(body, "{"+expr+"}", "?", 1)
	}
	// Append the parameter tuple at the end of the execute(...) call,
	// located by paren matching so trailing-comment parens can't mislead it.
	execPos := strings.Index(body, "execute")
	if execPos < 0 {
		return nil, "", false
	}
	open := execPos + len("execute")
	for open < len(body) && isWordByte(body[open]) {
		open++
	}
	for open < len(body) && isSpaceByte(body[open]) {
		open++
	}
	if open >= len(body) || body[open] != '(' {
		return nil, "", false
	}
	closeIdx, ok := findMatchingParen(body, open)
	if !ok {
		return nil, "", false
	}
	body = body[:closeIdx] + ", (" + expr + ",)" + body[closeIdx:]
	return nil, body, true
}

func isWordByte(b byte) bool {
	return b == '_' || (b >= 'a' && b <= 'z') || (b >= 'A' && b <= 'Z') || (b >= '0' && b <= '9')
}

func isSpaceByte(b byte) bool {
	return b == ' ' || b == '\t' || b == '\n' || b == '\r' || cIsSpace(b)
}

func cIsSpace(b byte) bool { return b == '\f' || b == '\v' }

// findMatchingParen returns the byte index of the `)` matching the `(` at
// open (quote-aware, bailing out at a `#` comment).
func findMatchingParen(s string, open int) (int, bool) {
	b := []byte(s)
	if open >= len(b) || b[open] != '(' {
		return 0, false
	}
	depth := 0
	var quote byte
	inQuote := false
	for i := open; i < len(b); i++ {
		ch := b[i]
		if inQuote {
			if ch == '\\' {
				i++
				continue
			}
			if ch == quote {
				inQuote = false
			}
		} else if ch == '"' || ch == '\'' {
			quote = ch
			inQuote = true
		} else if ch == '(' {
			depth++
		} else if ch == ')' {
			depth--
			if depth == 0 {
				return i, true
			}
		} else if ch == '#' {
			return 0, false
		}
	}
	return 0, false
}

func fixCMDi(line string) ([]string, string, bool) {
	if cap := cmdiRunRe.FindStringSubmatch(line); cap != nil {
		loc := cmdiRunRe.FindStringSubmatchIndex(line)
		before, v, after := cap[3], strings.TrimSpace(cap[4]), cap[5]
		// Exactly one interpolation; anything else gets an advisory comment.
		if !strings.ContainsAny(before, "{}") && !strings.ContainsAny(after, "{}") &&
			!strings.ContainsAny(before, "\"'\\") && !strings.ContainsAny(after, "\"'\\") &&
			identRe.MatchString(v) {
			var argv []string
			for _, t := range strings.Fields(before) {
				argv = append(argv, `"`+t+`"`)
			}
			argv = append(argv, v)
			for _, t := range strings.Fields(after) {
				argv = append(argv, `"`+t+`"`)
			}
			if len(argv) > 0 {
				body := line[:loc[0]] + cap[1] + "[" + strings.Join(argv, ", ") + "]" + line[loc[1]:]
				body = strings.ReplaceAll(body, "shell=True", "shell=False")
				return nil, body, true
			}
		}
	}
	// A bare shell flip is only safe when the command is already an argv
	// list; flipping a plain string would break the call at runtime.
	if strings.Contains(line, "shell=True") && subprocessListRe.MatchString(line) {
		return nil, strings.ReplaceAll(line, "shell=True", "shell=False"), true
	}
	return nil, "", false
}

func fixXSS(source, line string) ([]string, string, bool) {
	if !strings.Contains(line, "render_template_string") && !strings.Contains(line, "Markup") {
		return nil, "", false
	}
	if strings.Contains(line, "escape") {
		return nil, "", false
	}
	n1 := len(xssMidRe.FindAllString(line, -1))
	afterFirst := xssMidRe.ReplaceAllString(line, "+ html.escape($1) +")
	n2 := len(xssEndRe.FindAllString(afterFirst, -1))
	if n1+n2 == 0 {
		return nil, "", false
	}
	body := xssEndRe.ReplaceAllString(afterFirst, "+ html.escape($1))")
	return needImport(source, "html", "import html"), body, true
}

func fixPathTrav(source, line string) ([]string, string, bool) {
	loc := pathtravOpenRe.FindStringSubmatchIndex(line)
	if loc == nil {
		return nil, "", false
	}
	cap := pathtravOpenRe.FindStringSubmatch(line)
	var block []string
	if !strings.Contains(source, "_confined_path") {
		block = append(block, "\n")
		block = append(block, splitKeepEnds(ConfinedHelper)...)
	}
	body := line[:loc[0]] + "open(_confined_path(\"" + cap[1] + "\", " +
		strings.TrimSpace(cap[2]) + "))" + line[loc[1]:]
	return block, body, true
}

func fixDeser(source, line string) ([]string, string, bool) {
	if strings.Contains(line, "yaml.load(") && !strings.Contains(line, "Loader") && !strings.Contains(line, "safe_load") {
		return nil, strings.ReplaceAll(line, "yaml.load(", "yaml.safe_load("), true
	}
	if strings.Contains(line, "pickle.loads(") {
		return needImport(source, "json", "import json"),
			strings.ReplaceAll(line, "pickle.loads(", "json.loads("), true
	}
	if strings.Contains(line, "pickle.load(") {
		return needImport(source, "json", "import json"),
			strings.ReplaceAll(line, "pickle.load(", "json.load("), true
	}
	return nil, "", false
}

// BracketsBalanced is the best-effort syntax plausibility check used when
// no Python interpreter is available: brackets must balance outside
// strings and comments.
func BracketsBalanced(text string) bool {
	var stack []rune
	var quote rune
	inQuote := false
	triple := false
	chars := []rune(text)
	i := 0
	for i < len(chars) {
		c := chars[i]
		if inQuote {
			if c == '\\' {
				i += 2
				continue
			}
			if triple {
				if c == quote &&
					(i+1 >= len(chars) || chars[i+1] == quote) &&
					(i+2 >= len(chars) || chars[i+2] == quote) {
					i += 3
					inQuote = false
					triple = false
					continue
				}
				i++
				continue
			}
			if c == quote || c == '\n' {
				// Closing quote, or a newline ending an unterminated
				// single-line string (don't poison the rest of the file).
				inQuote = false
			}
			i++
			continue
		}
		switch c {
		case '"', '\'':
			triple = i+2 < len(chars) && chars[i+1] == c && chars[i+2] == c
			if triple {
				i += 3
			} else {
				i++
			}
			quote = c
			inQuote = true
		case '#':
			for i < len(chars) && chars[i] != '\n' {
				i++
			}
		case '(', '[', '{':
			stack = append(stack, c)
			i++
		case ')', ']', '}':
			if len(stack) == 0 {
				return false
			}
			open := stack[len(stack)-1]
			stack = stack[:len(stack)-1]
			if (open == '(' && c != ')') || (open == '[' && c != ']') || (open == '{' && c != '}') {
				return false
			}
			i++
		default:
			i++
		}
	}
	return len(stack) == 0 && !inQuote
}

func fixSecret(source, line string) ([]string, string, bool) {
	if strings.Contains(line, "os.environ") {
		return nil, "", false
	}
	stripped := strings.TrimSuffix(line, "\n")
	cap := secretAssignRe.FindStringSubmatch(stripped)
	if cap == nil {
		return nil, "", false
	}
	eol := ""
	if strings.HasSuffix(line, "\n") {
		eol = "\n"
	}
	body := cap[1] + cap[2] + ` = os.environ["` + cap[2] + `"]` + eol
	return needImport(source, "os", "import os"), body, true
}

func fixSSRF(source, line string) ([]string, string, bool) {
	loc := ssrfReqRe.FindStringSubmatchIndex(line)
	if loc == nil {
		return nil, "", false
	}
	cap := ssrfReqRe.FindStringSubmatch(line)
	var block []string
	if !strings.Contains(source, "_checked_url") {
		block = append(block, "\n")
		block = append(block, splitKeepEnds(CheckedURLHelper)...)
	}
	body := line[:loc[0]] + cap[1] + "_checked_url(" + strings.TrimSpace(cap[2]) + ")" + line[loc[1]:]
	return block, body, true
}

// DiffCtx is the unified-diff context radius.
const DiffCtx = 3

// structuredDiff builds a structured unified diff: one hunk for the
// top-of-file helper/import insertion (if any) plus one hunk for the sink
// change.
func structuredDiff(original, fixed []string, topPos, topLen, sinkIdx int, filePath string) string {
	if equalLines(original, fixed) {
		return ""
	}
	// fixed = original[..topPos] + topBlock + original[topPos..sinkIdx]
	//         + sinkNew + original[sinkIdx+1..]; slice the new parts out.
	fixedSinkStart := sinkIdx + topLen
	fixedSinkEnd := len(fixed) - (len(original) - (sinkIdx + 1))
	if topPos > len(original) || fixedSinkEnd < fixedSinkStart || fixedSinkEnd > len(fixed) {
		return spanningDiff(original, fixed, filePath)
	}
	topBlock := fixed[topPos : topPos+topLen]
	sinkNew := fixed[fixedSinkStart:fixedSinkEnd]

	// Top hunk uses below-only context so stacked top insertions from
	// earlier patches still match by content.
	topCtxEnd := topPos + DiffCtx
	if topCtxEnd > len(original) {
		topCtxEnd = len(original)
	}
	sinkStart := sinkIdx - DiffCtx
	if sinkStart < 0 {
		sinkStart = 0
	}
	sinkEnd := sinkIdx + 1 + DiffCtx
	if sinkEnd > len(original) {
		sinkEnd = len(original)
	}
	if topLen > 0 && sinkStart < topCtxEnd {
		// Regions overlap (sink near the top of the file): one hunk.
		return spanningDiff(original, fixed, filePath)
	}

	var diff strings.Builder
	fmt.Fprintf(&diff, "--- a/%s\n+++ b/%s\n", filePath, filePath)
	addedBefore := 0
	if topLen > 0 {
		old := original[topPos:topCtxEnd]
		newLines := make([]string, 0, len(topBlock)+len(old))
		newLines = append(newLines, topBlock...)
		newLines = append(newLines, old...)
		renderHunkAddedFirst(&diff, topPos, old, newLines, addedBefore)
		addedBefore += len(topBlock)
	}
	old := original[sinkStart:sinkEnd]
	newLines := make([]string, 0, len(old)+maxInt(len(sinkNew)-1, 0))
	newLines = append(newLines, original[sinkStart:sinkIdx]...)
	newLines = append(newLines, sinkNew...)
	newLines = append(newLines, original[sinkIdx+1:sinkEnd]...)
	preLen := sinkIdx - sinkStart
	renderHunkReplaceMiddle(&diff, sinkStart, old, newLines, addedBefore, preLen, 1)
	return diff.String()
}

func renderHunkAddedFirst(diff *strings.Builder, oldStart0 int, old, newLines []string, addedBefore int) {
	newStart0 := oldStart0 + addedBefore
	fmt.Fprintf(diff, "@@ -%d,%d +%d,%d @@\n", oldStart0+1, len(old), newStart0+1, len(newLines))
	for _, line := range newLines[:len(newLines)-len(old)] {
		diff.WriteByte('+')
		pushLine(diff, line)
	}
	for _, line := range old {
		diff.WriteByte(' ')
		pushLine(diff, line)
	}
}

func renderHunkReplaceMiddle(diff *strings.Builder, oldStart0 int, old, newLines []string, addedBefore, preLen, oldMidLen int) {
	newStart0 := oldStart0 + addedBefore
	fmt.Fprintf(diff, "@@ -%d,%d +%d,%d @@\n", oldStart0+1, len(old), newStart0+1, len(newLines))
	newMidLen := len(newLines) + oldMidLen - len(old)
	for _, line := range old[:preLen] {
		diff.WriteByte(' ')
		pushLine(diff, line)
	}
	for _, line := range old[preLen : preLen+oldMidLen] {
		diff.WriteByte('-')
		pushLine(diff, line)
	}
	for _, line := range newLines[preLen : preLen+newMidLen] {
		diff.WriteByte('+')
		pushLine(diff, line)
	}
	for _, line := range old[preLen+oldMidLen:] {
		diff.WriteByte(' ')
		pushLine(diff, line)
	}
}

// spanningDiff is the single-hunk fallback spanning the whole change.
func spanningDiff(original, fixed []string, filePath string) string {
	if equalLines(original, fixed) {
		return ""
	}
	prefix := 0
	for prefix < len(original) && prefix < len(fixed) && original[prefix] == fixed[prefix] {
		prefix++
	}
	suffix := 0
	for suffix < len(original)-prefix && suffix < len(fixed)-prefix &&
		original[len(original)-1-suffix] == fixed[len(fixed)-1-suffix] {
		suffix++
	}
	ctx := 3
	oStart := prefix - ctx
	if oStart < 0 {
		oStart = 0
	}
	oEnd := len(original) - suffix + ctx
	if oEnd > len(original) {
		oEnd = len(original)
	}
	preCtx := prefix - oStart
	sufCtx := oEnd - (len(original) - suffix)
	nStart := prefix - preCtx
	nEnd := len(fixed) - suffix + sufCtx
	if nEnd > len(fixed) {
		nEnd = len(fixed)
	}

	var diff strings.Builder
	fmt.Fprintf(&diff, "--- a/%s\n+++ b/%s\n", filePath, filePath)
	fmt.Fprintf(&diff, "@@ -%d,%d +%d,%d @@\n", oStart+1, oEnd-oStart, nStart+1, nEnd-nStart)
	for _, line := range original[oStart:prefix] {
		diff.WriteByte(' ')
		pushLine(&diff, line)
	}
	for _, line := range original[prefix : len(original)-suffix] {
		diff.WriteByte('-')
		pushLine(&diff, line)
	}
	for _, line := range fixed[prefix : len(fixed)-suffix] {
		diff.WriteByte('+')
		pushLine(&diff, line)
	}
	for _, line := range original[len(original)-suffix : oEnd] {
		diff.WriteByte(' ')
		pushLine(&diff, line)
	}
	return diff.String()
}

func pushLine(diff *strings.Builder, line string) {
	diff.WriteString(line)
	if !strings.HasSuffix(line, "\n") {
		diff.WriteByte('\n')
	}
}

func equalLines(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	for i := range a {
		if a[i] != b[i] {
			return false
		}
	}
	return true
}

// PythonSyntaxOK validates Python syntax via ast.parse. It returns
// hasInterp=false when no interpreter is available.
func PythonSyntaxOK(source string) (valid, hasInterp bool) {
	python, ok := sandbox.FindPython()
	if !ok {
		return false, false
	}
	cmd := exec.Command(python, "-c", "import ast,sys; ast.parse(sys.stdin.read())")
	stdin, err := cmd.StdinPipe()
	if err != nil {
		return false, false
	}
	cmd.Stdout = nil
	if err := cmd.Start(); err != nil {
		return false, false
	}
	_, werr := stdin.Write([]byte(source))
	stdin.Close()
	if werr != nil {
		cmd.Wait()
		return false, true
	}
	return cmd.Wait() == nil, true
}

func maxI64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}

func minI64(a, b int64) int64 {
	if a < b {
		return a
	}
	return b
}

func maxInt(a, b int) int {
	if a > b {
		return a
	}
	return b
}
