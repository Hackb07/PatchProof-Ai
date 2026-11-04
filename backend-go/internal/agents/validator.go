package agents

import (
	"context"
	"fmt"
	"strings"

	"github.com/patchproof/patchproof-go/internal/model"
	"github.com/patchproof/patchproof-go/internal/store"
	"github.com/patchproof/patchproof-go/internal/util"
)

// Validate confirms findings using repro evidence plus code context.
func Validate(ctx context.Context, st *store.Store, llm *LlmClient, scanID string) ([]model.Finding, error) {
	findings, err := st.ListFindings(scanID)
	if err != nil {
		return nil, err
	}
	for _, f := range findings {
		reproduced := "False"
		if f.Reproduced {
			reproduced = "True"
		}
		reply := llm.Chat(ctx,
			"You validate security findings. Reply VERDICT: TRUE_POSITIVE or VERDICT: FALSE_POSITIVE with REASON.",
			fmt.Sprintf("%s at %s:%d\n%s\nReproduced: %s. Repro log:\n%s",
				f.Title, f.FilePath, f.LineNo, f.Snippet, reproduced,
				util.TruncateChars(f.ReproLog, 1500)),
			800,
		).Output
		if isFalsePositive(reply) {
			err = st.UpdateFindingValidation(f.ID, false, true)
		} else {
			err = st.UpdateFindingValidation(f.ID, true, false)
		}
		if err != nil {
			return nil, err
		}
	}
	_, err = st.AddEvidence(scanID, "triage", "validator", "Validation pass complete", "")
	if err != nil {
		return nil, err
	}
	return findings, nil
}

// isFalsePositive parses `VERDICT: TRUE_POSITIVE|FALSE_POSITIVE`,
// preferring an explicitly labeled line. Unlabeled replies confirm the
// finding (matching the mock).
func isFalsePositive(output string) bool {
	for _, line := range strings.Split(output, "\n") {
		if rest, ok := strings.CutPrefix(strings.ToUpper(line), "VERDICT:"); ok {
			return strings.Contains(rest, "FALSE_POSITIVE")
		}
	}
	return false
}
