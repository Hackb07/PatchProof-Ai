"""LLM client with deterministic mock fallback for offline demos."""
from dataclasses import dataclass

import httpx

from ..config import settings


@dataclass
class AgentResult:
    output: str
    mock: bool = True


class LLMClient:
    def __init__(self) -> None:
        self.mock = settings.llm_mock or not settings.meta_api_key

    def chat(self, system: str, user: str, max_tokens: int = 800) -> AgentResult:
        if self.mock:
            return AgentResult(output=self._mock_reply(system, user), mock=True)
        try:
            resp = httpx.post(
                f"{settings.meta_api_base}/chat/completions",
                headers={"Authorization": f"Bearer {settings.meta_api_key}"},
                json={
                    "model": settings.meta_model,
                    "messages": [
                        {"role": "system", "content": system},
                        {"role": "user", "content": user},
                    ],
                    "max_tokens": max_tokens,
                    "temperature": 0.1,
                },
                timeout=30,
            )
            resp.raise_for_status()
            data = resp.json()
            return AgentResult(output=data["choices"][0]["message"]["content"], mock=False)
        except Exception as exc:  # fall back to mock rather than failing the pipeline
            return AgentResult(output=f"{self._mock_reply(system, user)}\n\n[llm-fallback: {exc}]", mock=True)

    @staticmethod
    def _mock_reply(system: str, user: str) -> str:
        low = (system + "\n" + user).lower()
        if "risk" in low or "score" in low:
            return "RISK_SCORE: 7.5\nRATIONALE: Mock assessment: tainted input reaches a dangerous sink without visible sanitization."
        if "validat" in low or "false positive" in low:
            return "VERDICT: TRUE_POSITIVE\nREASON: Mock validation: sink is reachable and no sanitizer was found nearby."
        if "triage" in low or "dedup" in low:
            return "TRIAGE: KEEP\nREASON: Mock triage: distinct sink line, keep for investigation."
        if "patch" in low or "diff" in low:
            return "PATCH_NOTE: Mock patch mode: use the deterministic fixer for a minimal safe edit."
        return "MOCK_OK: deterministic offline response."
