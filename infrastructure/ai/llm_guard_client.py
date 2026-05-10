import structlog
import httpx

from core.config import settings
from core.exceptions import PromptInjectionError

logger = structlog.get_logger()


class LLMGuardClient:
    """
    Valida input/output do Claude contra prompt injection.
    Obrigatório antes de toda chamada ao Claude — sem exceção.
    """

    def __init__(self) -> None:
        self._client = httpx.AsyncClient(
            base_url=settings.LLM_GUARD_BASE_URL,
            timeout=httpx.Timeout(30.0, connect=5.0),
        )

    async def validate_input(self, prompt: str) -> tuple[str, bool]:
        """Retorna (sanitized_prompt, is_valid). Bloqueia se injection detectada."""
        if not settings.LLM_GUARD_ENABLED:
            return prompt, True

        try:
            response = await self._client.post(
                "/analyze/output",
                json={"prompt": prompt},
            )
            response.raise_for_status()
            data = response.json()
        except httpx.HTTPError as exc:
            logger.warning("llm_guard_unavailable", error=str(exc))
            raise PromptInjectionError("LLM Guard indisponível — chamada ao Claude bloqueada") from exc

        is_valid = data.get("is_valid", False)
        sanitized = data.get("sanitized_prompt", prompt)
        return sanitized, is_valid

    async def validate_output(self, output: str) -> tuple[str, bool]:
        """Valida output do Claude — detecta exfiltração de dados sensíveis."""
        if not settings.LLM_GUARD_ENABLED:
            return output, True

        try:
            response = await self._client.post(
                "/analyze/output",
                json={"output": output},
            )
            response.raise_for_status()
            data = response.json()
        except httpx.HTTPError as exc:
            logger.warning("llm_guard_output_check_failed", error=str(exc))
            return output, True

        is_valid = data.get("is_valid", True)
        sanitized = data.get("sanitized_output", output)
        return sanitized, is_valid
