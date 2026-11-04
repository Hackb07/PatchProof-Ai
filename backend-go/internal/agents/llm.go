// Package agents ports crates/core/src/agents: the LLM client plus the
// triage, risk, and validation passes.
package agents

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"strings"
	"time"

	"github.com/patchproof/patchproof-go/internal/config"
)

// AgentResult is one LLM call outcome.
type AgentResult struct {
	Output string
	Mock   bool
}

// LlmClient talks to a Meta chat-completions endpoint, or answers
// deterministically in mock mode.
type LlmClient struct {
	mock    bool
	apiKey  string
	apiBase string
	model   string
	http    *http.Client
}

// NewLlmClient builds a client from settings.
func NewLlmClient(s config.Settings) *LlmClient {
	return &LlmClient{
		mock:    s.LLMMock || s.MetaAPIKey == "",
		apiKey:  s.MetaAPIKey,
		apiBase: s.MetaAPIBase,
		model:   s.MetaModel,
		http:    &http.Client{Timeout: 30 * time.Second},
	}
}

// IsMock reports whether the client answers deterministically.
func (c *LlmClient) IsMock() bool { return c.mock }

// Chat sends one system/user turn with a token cap.
func (c *LlmClient) Chat(ctx context.Context, system, user string, maxTokens uint32) AgentResult {
	if c.mock {
		return AgentResult{Output: MockReply(system, user), Mock: true}
	}
	output, err := c.liveChat(ctx, system, user, maxTokens)
	if err != nil {
		return AgentResult{
			Output: fmt.Sprintf("%s\n\n[llm-fallback: %s]", MockReply(system, user), err),
			Mock:   true,
		}
	}
	return AgentResult{Output: output}
}

func (c *LlmClient) liveChat(ctx context.Context, system, user string, maxTokens uint32) (string, error) {
	body, err := json.Marshal(map[string]any{
		"model": c.model,
		"messages": []map[string]string{
			{"role": "system", "content": system},
			{"role": "user", "content": user},
		},
		"max_tokens":  maxTokens,
		"temperature": 0.1,
	})
	if err != nil {
		return "", err
	}
	ctx, cancel := context.WithTimeout(ctx, 30*time.Second)
	defer cancel()
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.apiBase+"/chat/completions", bytes.NewReader(body))
	if err != nil {
		return "", err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("Authorization", "Bearer "+c.apiKey)
	resp, err := c.http.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	data, err := io.ReadAll(io.LimitReader(resp.Body, 1<<20))
	if err != nil {
		return "", err
	}
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return "", fmt.Errorf("LLM HTTP %d", resp.StatusCode)
	}
	var parsed struct {
		Choices []struct {
			Message struct {
				Content string `json:"content"`
			} `json:"message"`
		} `json:"choices"`
	}
	if err := json.Unmarshal(data, &parsed); err != nil {
		return "", err
	}
	if len(parsed.Choices) == 0 {
		return "", fmt.Errorf("missing choices[0].message.content")
	}
	return parsed.Choices[0].Message.Content, nil
}

// MockReply is the deterministic offline answer, keyed off the prompt.
func MockReply(system, user string) string {
	low := strings.ToLower(system + "\n" + user)
	if strings.Contains(low, "risk") || strings.Contains(low, "score") {
		return "RISK_SCORE: 7.5\nRATIONALE: Mock assessment: tainted input reaches a dangerous sink without visible sanitization."
	}
	if strings.Contains(low, "validat") || strings.Contains(low, "false positive") {
		return "VERDICT: TRUE_POSITIVE\nREASON: Mock validation: sink is reachable and no sanitizer was found nearby."
	}
	if strings.Contains(low, "triage") || strings.Contains(low, "dedup") {
		return "TRIAGE: KEEP\nREASON: Mock triage: distinct sink line, keep for investigation."
	}
	if strings.Contains(low, "patch") || strings.Contains(low, "diff") {
		return "PATCH_NOTE: Mock patch mode: use the deterministic fixer for a minimal safe edit."
	}
	return "MOCK_OK: deterministic offline response."
}
