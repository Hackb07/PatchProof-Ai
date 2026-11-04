package agents

import (
	"context"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"

	"github.com/patchproof/patchproof-go/internal/model"
	"github.com/patchproof/patchproof-go/internal/store"
	"github.com/patchproof/patchproof-go/internal/util"
)

// SeverityPrior maps a severity to its base risk score.
func SeverityPrior(severity string) float64 {
	switch severity {
	case "critical":
		return 9.0
	case "high":
		return 7.5
	case "medium":
		return 5.0
	case "low":
		return 2.5
	default:
		return 5.0
	}
}

var riskScoreRe = regexp.MustCompile(`(?i)RISK_SCORE:\s*([0-9]+(?:\.[0-9]+)?)`)

// Assess scores each finding 0-10 with a rationale.
func Assess(ctx context.Context, st *store.Store, llm *LlmClient, scanID string) ([]model.Finding, error) {
	findings, err := st.ListFindings(scanID)
	if err != nil {
		return nil, err
	}
	for _, f := range findings {
		var reply string
		var score float64
		if llm.IsMock() {
			score = SeverityPrior(f.Severity)
			if f.Confidence == "low" {
				score = math.Max(score-1.5, 1.0)
			} else if f.Confidence == "high" {
				score = math.Min(score+0.5, 10.0)
			}
			reply = fmt.Sprintf(
				"RISK_SCORE: %s\nRATIONALE: Mock heuristic: %s severity, %s confidence, %s. Connect a Meta model for contextual scoring.",
				fmtScore(score), f.Severity, f.Confidence, f.CWE,
			)
		} else {
			reply = llm.Chat(ctx,
				"You are a security risk assessor. Reply with RISK_SCORE: <0-10> and RATIONALE: <one paragraph>.",
				fmt.Sprintf("Severity %s confidence %s. %s (%s) at %s:%d\n%s\n%s",
					f.Severity, f.Confidence, f.Title, f.CWE, f.FilePath, f.LineNo, f.Snippet, f.Explanation),
				800,
			).Output
			score = SeverityPrior(f.Severity)
			if parsed, ok := parseScore(reply); ok {
				score = parsed
			}
			if f.Confidence == "low" {
				score = math.Max(score-1.5, 1.0)
			}
		}
		clamped := math.Min(math.Max(score, 0.0), 10.0)
		rounded := math.Round(clamped*10.0) / 10.0
		if err := st.UpdateFindingRisk(f.ID, rounded, util.TruncateChars(strings.TrimSpace(reply), 2000)); err != nil {
			return nil, err
		}
	}
	_, err = st.AddEvidence(scanID, "risk", "risk-assessor",
		fmt.Sprintf("Risk scoring complete for %d findings", len(findings)), "")
	if err != nil {
		return nil, err
	}
	return findings, nil
}

func parseScore(text string) (float64, bool) {
	m := riskScoreRe.FindStringSubmatch(text)
	if len(m) < 2 {
		return 0, false
	}
	v, err := strconv.ParseFloat(m[1], 64)
	if err != nil {
		return 0, false
	}
	return v, true
}

// fmtScore matches Python str(float) for whole-number scores (`5.0`, not `5`).
func fmtScore(score float64) string {
	if score == math.Trunc(score) {
		return strconv.FormatFloat(score, 'f', 1, 64)
	}
	return strconv.FormatFloat(score, 'g', -1, 64)
}
