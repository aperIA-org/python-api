import json
import re

import anthropic
import structlog

from core.config import settings
from infrastructure.ai.llm_guard_client import LLMGuardClient

logger = structlog.get_logger()

MODEL = "claude-sonnet-4-20250514"


class ClaudeClient:
    def __init__(self) -> None:
        self.client = anthropic.Anthropic(api_key=settings.ANTHROPIC_API_KEY)
        self.guard = LLMGuardClient()

    def call(
        self,
        system: str,
        user_prompt: str,
        commit_sha: str = "",
        max_tokens: int = 8192,
    ) -> str:
        sanitized_prompt = self.guard.validate_input(user_prompt, commit_sha)

        response = self.client.messages.create(
            model=MODEL,
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": sanitized_prompt}],
        )
        output = response.content[0].text

        logger.info(
            "claude_call_done",
            commit_sha=commit_sha,
            input_tokens=response.usage.input_tokens,
            output_tokens=response.usage.output_tokens,
        )

        return self.guard.validate_output(sanitized_prompt, output, commit_sha)

    def call_json(
        self,
        system: str,
        user_prompt: str,
        commit_sha: str = "",
        max_tokens: int = 8192,
    ) -> dict:
        raw = self.call(system, user_prompt, commit_sha, max_tokens)
        return parse_json_response(raw)


def parse_json_response(text: str) -> dict:
    clean = re.sub(r"```(?:json)?\n?(.*?)```", r"\1", text, flags=re.DOTALL).strip()
    try:
        return json.loads(clean)
    except json.JSONDecodeError as exc:
        logger.error("json_parse_error", error=str(exc), raw_preview=text[:300])
        raise
