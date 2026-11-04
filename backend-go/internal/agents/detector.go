package agents

import (
	"context"
	"fmt"
	"strings"

	"github.com/patchproof/patchproof-go/internal/model"
	"github.com/patchproof/patchproof-go/internal/store"
)

// Triage dedupes raw findings and drops LLM-rejected ones.
func Triage(ctx context.Context, st *store.Store, llm *LlmClient, scanID string) ([]model.Finding, error) {
	findings, err := st.ListFindings(scanID)
	if err != nil {
		return nil, err
	}
	total := len(findings)
	var kept []model.Finding
	type key struct {
		rule, file string
		line       int64
	}
	seen := make(map[key]bool)
	for _, f := range findings {
		k := key{f.RuleID, f.FilePath, f.LineNo}
		if seen[k] {
			if err := st.DeleteFinding(f.ID); err != nil {
				return nil, err
			}
			continue
		}
		seen[k] = true
		verdict := llm.Chat(ctx,
			"You triage static-analysis findings. Reply TRIAGE: KEEP or TRIAGE: DROP with a reason.",
			fmt.Sprintf("Rule %s %s at %s:%d\n%s\n%s",
				f.RuleID, f.Title, f.FilePath, f.LineNo, f.Snippet, f.Explanation),
			800,
		).Output
		if keepVerdict(verdict) {
			kept = append(kept, f)
		} else if err := st.DeleteFinding(f.ID); err != nil {
			return nil, err
		}
	}
	_, err = st.AddEvidence(scanID, "triage", "detector",
		fmt.Sprintf("Triage complete: %d/%d findings kept", len(kept), total), "")
	if err != nil {
		return nil, err
	}
	return kept, nil
}

// keepVerdict parses `TRIAGE: KEEP|DROP`, preferring an explicitly labeled
// line so a free-text mention of "drop" can't discard a finding. Unlabeled
// replies keep the finding (matching the mock).
func keepVerdict(output string) bool {
	for _, line := range strings.Split(output, "\n") {
		if rest, ok := strings.CutPrefix(strings.ToUpper(line), "TRIAGE:"); ok {
			return !strings.Contains(rest, "DROP")
		}
	}
	return true
}
