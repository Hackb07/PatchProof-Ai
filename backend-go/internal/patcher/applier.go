package patcher

import (
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

// SearchRadius is how far (in lines) from a hunk's recorded position to
// search for its expected content before giving up.
const SearchRadius = 80

type hunk struct {
	start    int
	oldLines []string
	newLines []string
}

// ApplyDiff applies a unified diff produced by the patcher. Every hunk
// must match its expected old lines at (or near) the recorded position;
// a hunk that matches nowhere fails the whole application.
func ApplyDiff(repoPath, diff string) bool {
	targetRel, hunks := parseDiff(diff)
	if targetRel == "" || len(hunks) == 0 {
		return false
	}
	// Defense in depth: never write outside the checkout or through a link.
	if strings.Contains(targetRel, "..") || filepath.IsAbs(targetRel) {
		return false
	}
	target := filepath.Join(repoPath, targetRel)
	if fi, err := os.Lstat(target); err != nil || fi.Mode()&os.ModeSymlink != 0 {
		if err == nil {
			return false
		}
		// Missing file falls through to the read below, which fails.
		if !os.IsNotExist(err) {
			return false
		}
	}
	bytes, err := os.ReadFile(target)
	if err != nil {
		return false
	}
	content := strings.ToValidUTF8(string(bytes), "\uFFFD")
	lines := splitKeepEnds(content)
	// Apply bottom-up so earlier hunk positions stay valid; each hunk is
	// still content-verified before splicing.
	order := make([]int, len(hunks))
	for i := range hunks {
		order[i] = i
	}
	sort.Slice(order, func(a, b int) bool { return hunks[order[a]].start > hunks[order[b]].start })
	for _, i := range order {
		var ok bool
		lines, ok = applyHunk(lines, hunks[i])
		if !ok {
			return false
		}
	}
	return os.WriteFile(target, []byte(strings.Join(lines, "")), 0o644) == nil
}

func applyHunk(lines []string, h hunk) ([]string, bool) {
	if len(h.oldLines) == 0 {
		idx := h.start - 1
		if idx < 0 {
			idx = 0
		}
		if idx > len(lines) {
			idx = len(lines)
		}
		out := make([]string, 0, len(lines)+len(h.newLines))
		out = append(out, lines[:idx]...)
		out = append(out, h.newLines...)
		out = append(out, lines[idx:]...)
		return out, true
	}
	expected := h.start - 1
	if expected < 0 {
		expected = 0
	}
	if expected > len(lines) {
		expected = len(lines)
	}
	if matchesAt(lines, expected, h.oldLines) {
		return spliceAt(lines, expected, h), true
	}
	// Search outward from the expected position: earlier patches may have
	// shifted the hunk's content.
	for dist := 1; dist <= SearchRadius; dist++ {
		lo := expected - dist
		if lo < 0 {
			lo = 0
		}
		if matchesAt(lines, lo, h.oldLines) {
			return spliceAt(lines, lo, h), true
		}
		hi := expected + dist
		if matchesAt(lines, hi, h.oldLines) {
			return spliceAt(lines, hi, h), true
		}
	}
	return lines, false
}

func matchesAt(lines []string, idx int, old []string) bool {
	if idx < 0 || idx+len(old) > len(lines) {
		return false
	}
	for i, l := range old {
		if lines[idx+i] != l {
			return false
		}
	}
	return true
}

func spliceAt(lines []string, idx int, h hunk) []string {
	end := idx + len(h.oldLines)
	if end > len(lines) {
		end = len(lines)
	}
	out := make([]string, 0, len(lines)-len(h.oldLines)+len(h.newLines))
	out = append(out, lines[:idx]...)
	out = append(out, h.newLines...)
	out = append(out, lines[end:]...)
	return out
}

var hunkRe = regexp.MustCompile(`^@@ -(\d+)(?:,(\d+))? \+(\d+)(?:,(\d+))? @@`)

func parseDiff(diff string) (string, []hunk) {
	target := ""
	var hunks []hunk
	current := -1
	for _, line := range splitKeepEnds(diff) {
		if rest, ok := strings.CutPrefix(line, "+++ b/"); ok {
			target = strings.TrimSpace(rest)
		} else if strings.HasPrefix(line, "@@") {
			if cap := hunkRe.FindStringSubmatch(line); cap != nil {
				start := 1
				if n, err := strconv.Atoi(cap[1]); err == nil {
					start = n
				}
				hunks = append(hunks, hunk{start: start})
				current = len(hunks) - 1
			}
		} else if current >= 0 {
			if strings.HasPrefix(line, "+") && !strings.HasPrefix(line, "+++") {
				hunks[current].newLines = append(hunks[current].newLines, line[1:])
			} else if stripped, ok := strings.CutPrefix(line, " "); ok {
				hunks[current].oldLines = append(hunks[current].oldLines, stripped)
				hunks[current].newLines = append(hunks[current].newLines, stripped)
			} else if strings.HasPrefix(line, "-") && !strings.HasPrefix(line, "---") {
				hunks[current].oldLines = append(hunks[current].oldLines, line[1:])
			}
			// `\ No newline at end of file` markers carry no content.
		}
	}
	return target, hunks
}
