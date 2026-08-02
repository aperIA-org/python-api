"""Claude client com circuit breaker, LLM Guard e instrumentação de custo.

Princípios:

- O system prompt é cacheado via ``cache_control: ephemeral`` para que
  chamadas subsequentes (dentro de 5 min) paguem apenas 10% do custo
  do bloco system.
- Model routing: o caller escolhe ``REASONING`` (Sonnet) ou
  ``FORMATTING`` (Haiku) via constantes em ``ai/models.py``. Nunca
  passar string literal.
- Circuit breaker compartilhado de processo: 3 falhas → abre 5 min;
  enquanto aberto, o método retorna ``CircuitOpenError`` sem chamar
  a API.
- LLM Guard: o ``user`` é checado antes de toda chamada. Se houver
  prompt injection detectada, levanta ``GuardBlockedError`` e o caller
  decide degradar (ex: pular Claude e retornar findings brutos).
- Token usage é registrado no Prometheus, separando fresh / cache_read
  / cache_write para custo correto.
"""
from __future__ import annotations

import json
import re
from dataclasses import dataclass
from typing import Any

import structlog
from anthropic import Anthropic, AnthropicError

from app.config import settings
from app.infrastructure.ai.circuit_breaker import DEFAULT_BREAKER, CircuitBreaker
from app.infrastructure.ai.llm_guard_client import LLMGuardClient, redigir_segredos
from app.infrastructure.ai.models import FORMATTING, REASONING
from app.infrastructure.ai.token_metrics import (
    record_request_outcome,
    record_token_usage,
)

logger = structlog.get_logger()


# Faixas de emoji, símbolos e dingbats. As acentuadas do português vivem no
# Latin-1 Supplement (bem abaixo de U+2600) e os travessões usados nos
# relatórios são U+2013/U+2014 — nenhum deles é tocado.
_EMOJI = re.compile(
    "["
    "\U0001F000-\U0001FAFF"   # emoji, pictogramas, símbolos suplementares
    "\u2600-\u27BF"           # símbolos diversos e dingbats (inclui ✓ e ⚠)
    "\u2B00-\u2BFF"           # setas e formas
    "\uFE0F"                   # seletor de variação (o "️" de 🛡️)
    "\u200D"                   # zero-width joiner (emojis compostos)
    "]+"
)


def remover_emojis(texto: str) -> str:
    """Tira emojis do texto gerado pelo modelo.

    O prompt já pede para não usar, mas **instrução não é contrato**: o modelo
    decora relatório de segurança por conta própria com frequência, e o
    relatório vai para PR, dashboard e export — lugares onde ícone atrapalha
    mais do que ajuda. Aqui a remoção é determinística.

    Colapsa o espaço duplo que sobra quando o emoji estava entre palavras.
    """
    return re.sub(r"[ \t]{2,}", " ", _EMOJI.sub("", texto)).strip()


class ClaudeClientError(Exception):
    """Erro base para falhas do ClaudeClient."""


class CircuitOpenError(ClaudeClientError):
    """O circuit breaker está aberto — chamada não tentada."""


class GuardBlockedError(ClaudeClientError):
    """LLM Guard bloqueou o conteúdo (provável prompt injection)."""

    def __init__(self, reason: str, pattern: str | None = None) -> None:
        super().__init__(f"Guard blocked: {reason}")
        self.reason = reason
        self.pattern = pattern


@dataclass
class ClaudeResponse:
    text: str
    model: str
    input_tokens: int
    output_tokens: int
    cache_read_tokens: int
    cache_write_tokens: int

    @property
    def stop_reason(self) -> str | None:  # placeholder para futura instrumentação
        return None


class ClaudeClient:
    """Wrapper síncrono da Anthropic SDK com hardening.

    Síncrono é proposital — workers Celery são síncronos. A integração
    com FastAPI async é feita via ``asyncio.to_thread()`` quando
    necessário.
    """

    def __init__(
        self,
        *,
        api_key: str | None = None,
        guard: LLMGuardClient | None = None,
        breaker: CircuitBreaker | None = None,
        anthropic_client: Anthropic | None = None,
    ) -> None:
        self._api_key = api_key or settings.ANTHROPIC_API_KEY
        self._guard = guard or LLMGuardClient()
        self._breaker = breaker or DEFAULT_BREAKER
        # Permite injeção em testes; senão constrói com a key dos settings.
        self._client = anthropic_client or Anthropic(api_key=self._api_key)

    def call(
        self,
        *,
        system: str,
        user: str,
        model: str,
        max_tokens: int = 4096,
        commit_sha: str = "",
    ) -> ClaudeResponse:
        if self._breaker.is_open():
            record_request_outcome(model, "circuit_open")
            raise CircuitOpenError("Claude API circuit breaker is OPEN")

        # Redigir ANTES da guarda, e num único ponto de estrangulamento: toda
        # chamada ao Claude passa por aqui, independente de qual prompt a
        # montou. Foi o que o incidente mostrou — o bloqueio não vinha do
        # `chain_of_events` (que nem inclui `description`) e sim do relatório do
        # Tier 2, que recebe os findings completos. Redigir no builder teria
        # consertado um caminho e deixado os outros.
        user, segredos_redigidos = redigir_segredos(user)
        if segredos_redigidos:
            logger.info(
                "prompt_segredos_redigidos",
                model=model,
                commit_sha=commit_sha,
                total=segredos_redigidos,
            )

        guard_result = self._guard.check(user)
        if not guard_result.safe:
            record_request_outcome(model, "blocked_by_guard")
            raise GuardBlockedError(
                guard_result.reason or "unknown", pattern=guard_result.pattern
            )

        system_blocks: list[dict[str, Any]] = [
            {
                "type": "text",
                "text": system,
                "cache_control": {"type": "ephemeral"},
            }
        ]
        if not settings.CLAUDE_PROMPT_CACHE_ENABLED:
            # remove o cache_control quando o caching está desligado
            system_blocks[0].pop("cache_control", None)

        try:
            message = self._client.messages.create(
                model=model,
                system=system_blocks,
                messages=[{"role": "user", "content": user}],
                max_tokens=max_tokens,
            )
        except AnthropicError as exc:
            self._breaker.record_failure()
            record_request_outcome(model, "error")
            logger.warning(
                "claude_api_error",
                model=model,
                commit_sha=commit_sha,
                error=str(exc),
                failures=self._breaker.failures,
            )
            raise ClaudeClientError(str(exc)) from exc

        self._breaker.record_success()
        record_request_outcome(model, "success")

        text = remover_emojis(self._extract_text(message))
        usage = getattr(message, "usage", None)
        input_tokens = int(getattr(usage, "input_tokens", 0) or 0)
        output_tokens = int(getattr(usage, "output_tokens", 0) or 0)
        cache_read = int(getattr(usage, "cache_read_input_tokens", 0) or 0)
        cache_write = int(getattr(usage, "cache_creation_input_tokens", 0) or 0)

        record_token_usage(
            model=model,
            input_tokens=input_tokens,
            cache_read_tokens=cache_read,
            cache_write_tokens=cache_write,
            output_tokens=output_tokens,
            commit_sha=commit_sha,
        )

        return ClaudeResponse(
            text=text,
            model=model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            cache_read_tokens=cache_read,
            cache_write_tokens=cache_write,
        )

    def call_json(
        self,
        *,
        system: str,
        user: str,
        model: str,
        max_tokens: int = 4096,
        commit_sha: str = "",
    ) -> dict:
        """Variante que parseia a resposta como JSON.

        Tolera fences de markdown (``json ...``) que o modelo
        frequentemente coloca ao redor de blocos JSON.
        """
        response = self.call(
            system=system,
            user=user,
            model=model,
            max_tokens=max_tokens,
            commit_sha=commit_sha,
        )
        return self._parse_json(response.text)

    @staticmethod
    def _extract_text(message: Any) -> str:
        content = getattr(message, "content", None)
        if isinstance(content, str):
            return content
        if isinstance(content, list):
            chunks: list[str] = []
            for block in content:
                text = getattr(block, "text", None)
                if isinstance(block, dict):
                    text = block.get("text")
                if isinstance(text, str):
                    chunks.append(text)
            return "".join(chunks)
        return ""

    @staticmethod
    def _parse_json(text: str) -> dict:
        stripped = text.strip()
        if stripped.startswith("```"):
            # remove fence inicial ```json (ou ``` puro)
            stripped = stripped.split("\n", 1)[1] if "\n" in stripped else ""
            if stripped.endswith("```"):
                stripped = stripped[: -3].rstrip()
        try:
            return json.loads(stripped)
        except json.JSONDecodeError as exc:
            raise ClaudeClientError(f"Resposta não é JSON válido: {exc}") from exc


# Exporta as constantes de modelo para que callers não precisem importar
# do módulo ``models`` separadamente (ergonomia).
__all__ = [
    "ClaudeClient",
    "ClaudeClientError",
    "ClaudeResponse",
    "CircuitOpenError",
    "GuardBlockedError",
    "FORMATTING",
    "REASONING",
]
