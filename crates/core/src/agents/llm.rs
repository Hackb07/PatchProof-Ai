//! LLM client with deterministic mock fallback (ports
//! `backend/app/agents/base.py`).

use std::time::Duration;

use crate::config::Settings;

#[derive(Debug, Clone)]
pub struct AgentResult {
    pub output: String,
    pub mock: bool,
}

#[derive(Debug, Clone)]
pub struct LlmClient {
    mock: bool,
    api_key: String,
    api_base: String,
    model: String,
    http: reqwest::Client,
}

impl LlmClient {
    pub fn new(settings: &Settings) -> Self {
        Self {
            mock: settings.llm_mock || settings.meta_api_key.is_empty(),
            api_key: settings.meta_api_key.clone(),
            api_base: settings.meta_api_base.clone(),
            model: settings.meta_model.clone(),
            http: reqwest::Client::new(),
        }
    }

    pub fn is_mock(&self) -> bool {
        self.mock
    }

    pub async fn chat(&self, system: &str, user: &str, max_tokens: u32) -> AgentResult {
        if self.mock {
            return AgentResult {
                output: Self::mock_reply(system, user),
                mock: true,
            };
        }
        match self.live_chat(system, user, max_tokens).await {
            Ok(output) => AgentResult {
                output,
                mock: false,
            },
            Err(exc) => AgentResult {
                output: format!(
                    "{}\n\n[llm-fallback: {exc}]",
                    Self::mock_reply(system, user)
                ),
                mock: true,
            },
        }
    }

    async fn live_chat(
        &self,
        system: &str,
        user: &str,
        max_tokens: u32,
    ) -> std::result::Result<String, String> {
        let url = format!("{}/chat/completions", self.api_base);
        let body = serde_json::json!({
            "model": self.model,
            "messages": [
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ],
            "max_tokens": max_tokens,
            "temperature": 0.1,
        });
        let resp = self
            .http
            .post(url)
            .bearer_auth(&self.api_key)
            .json(&body)
            .timeout(Duration::from_secs(30))
            .send()
            .await
            .map_err(|e| e.to_string())?;
        let resp = resp.error_for_status().map_err(|e| e.to_string())?;
        let data: serde_json::Value = resp.json().await.map_err(|e| e.to_string())?;
        data["choices"][0]["message"]["content"]
            .as_str()
            .map(|s| s.to_string())
            .ok_or_else(|| "missing choices[0].message.content".to_string())
    }

    fn mock_reply(system: &str, user: &str) -> String {
        let low = format!("{system}\n{user}").to_ascii_lowercase();
        if low.contains("risk") || low.contains("score") {
            return "RISK_SCORE: 7.5\nRATIONALE: Mock assessment: tainted input reaches a dangerous sink without visible sanitization.".to_string();
        }
        if low.contains("validat") || low.contains("false positive") {
            return "VERDICT: TRUE_POSITIVE\nREASON: Mock validation: sink is reachable and no sanitizer was found nearby.".to_string();
        }
        if low.contains("triage") || low.contains("dedup") {
            return "TRIAGE: KEEP\nREASON: Mock triage: distinct sink line, keep for investigation.".to_string();
        }
        if low.contains("patch") || low.contains("diff") {
            return "PATCH_NOTE: Mock patch mode: use the deterministic fixer for a minimal safe edit."
                .to_string();
        }
        "MOCK_OK: deterministic offline response.".to_string()
    }
}
