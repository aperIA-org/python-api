import structlog
import anthropic

from core.config import settings
from core.exceptions import PromptInjectionError
from infrastructure.ai.llm_guard_client import LLMGuardClient

logger = structlog.get_logger()

MODEL = "claude-sonnet-4-20250514"


class ClaudeClient:
    def __init__(self, guard: LLMGuardClient | None = None) -> None:
        self._client = anthropic.Anthropic(api_key=settings.ANTHROPIC_API_KEY)
        self._guard = guard or LLMGuardClient()

    async def call(
        self,
        system: str,
        user_prompt: str,
        commit_sha: str,
        max_tokens: int = 8192,
    ) -> str:
        log = logger.bind(commit_sha=commit_sha, model=MODEL)

        sanitized, is_valid = await self._guard.validate_input(user_prompt)
        if not is_valid:
            log.warning("llm_guard_blocked_input", reason="prompt_injection_detected")
            raise PromptInjectionError(
                f"Input bloqueado pelo LLM Guard para commit {commit_sha}. "
                "Possível prompt injection no conteúdo do repositório."
            )

        log.info("claude_request_sent", tokens_estimate=len(sanitized) // 4)

        response = self._client.messages.create(
            model=MODEL,
            max_tokens=max_tokens,
            system=system,
            messages=[{"role": "user", "content": sanitized}],
        )
        output = response.content[0].text

        sanitized_output, output_valid = await self._guard.validate_output(output)
        if not output_valid:
            log.warning("llm_guard_blocked_output", commit_sha=commit_sha)

        log.info("claude_response_received", output_tokens=response.usage.output_tokens)
        return sanitized_output
