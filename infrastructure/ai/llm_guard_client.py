import structlog
from llm_guard import scan_prompt, scan_output
from llm_guard.input_scanners import PromptInjection, Secrets, TokenLimit
from llm_guard.output_scanners import Sensitive, NoRefusal

from core.config import settings
from core.exceptions import PromptInjectionError

logger = structlog.get_logger()

INPUT_SCANNERS = [
    PromptInjection(),
    Secrets(),
    TokenLimit(limit=4096),
]

OUTPUT_SCANNERS = [
    Sensitive(),
    NoRefusal(),
]


class LLMGuardClient:
    """
    Valida input/output do Claude contra prompt injection via biblioteca llm_guard.
    Obrigatório antes de toda chamada ao Claude — sem exceção.
    """

    def validate_input(self, prompt: str, commit_sha: str = "") -> str:
        """
        Sanitiza e valida o prompt antes de enviar ao Claude.
        Levanta PromptInjectionError se injection detectada.
        Retorna o prompt sanitizado.
        """
        if not settings.LLM_GUARD_ENABLED:
            return prompt

        sanitized, results, is_valid = scan_prompt(INPUT_SCANNERS, prompt)
        if not is_valid:
            blocked_by = [name for name, r in results.items() if not r.is_valid]
            logger.warning(
                "llm_guard_input_blocked",
                commit_sha=commit_sha,
                blocked_by=blocked_by,
            )
            raise PromptInjectionError(
                f"Input bloqueado pelo LLM Guard (scanners: {blocked_by}). "
                f"Possível prompt injection no conteúdo do commit {commit_sha}."
            )
        return sanitized

    def validate_output(self, prompt: str, output: str, commit_sha: str = "") -> str:
        """
        Sanitiza o output do Claude — não levanta exceção, retorna output sanitizado.
        Log de warning se dados sensíveis forem detectados.
        """
        if not settings.LLM_GUARD_ENABLED:
            return output

        sanitized, results, is_valid = scan_output(
            INPUT_SCANNERS, OUTPUT_SCANNERS, prompt=prompt, output=output
        )
        if not is_valid:
            logger.warning("llm_guard_output_sanitized", commit_sha=commit_sha)
        return sanitized
