"""LLM Guard — stub heurístico para o MVP.

Por que stub e não a biblioteca real: a versão completa (``llm-guard``
no PyPI) traz PyTorch + transformers (~1 GB), tempo de boot alto, e
para o MVP precisamos apenas barrar os ataques mais óbvios. Esse
módulo será trocado pela lib real pós-MVP quando a precisão da
sanitização for prioridade.

Padrões detectados (regex case-insensitive):

- ``ignore (all|previous) instructions`` — injection clássica
- ``forget (all|everything) ...`` — variação
- ``you are now ...`` — tentativa de troca de persona
- ``system:`` / ``[INST]`` / ``</s>`` — tokens de fronteira de prompt
- ``__import__`` / ``eval(`` / ``exec(`` — exfiltração ou code-exec
- ``BEGIN PGP PRIVATE KEY`` — exfiltração de chave
- ``${jndi:`` — Log4Shell-style payload em comentário

Falha aberta: se o input contém um padrão, retorna ``BlockedResult``;
caller decide o que fazer (bypass do Claude, retornar findings brutos
sem narrativa, log de warning). Nunca propaga exception.
"""
from __future__ import annotations

import re
from dataclasses import dataclass

import structlog

from app.config import settings

logger = structlog.get_logger()


_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(all\s+)?(previous|prior|the\s+above)\s+instructions", re.I),
    re.compile(r"forget\s+(all|everything|previous|the\s+above)", re.I),
    re.compile(r"you\s+are\s+now\s+a", re.I),
    re.compile(r"disregard\s+(all|previous|the\s+above)", re.I),
    re.compile(r"override\s+(all|previous|safety|the\s+above)", re.I),
    re.compile(r"reveal\s+(your|the)\s+(system\s+)?prompt", re.I),
    re.compile(r"^\s*system\s*:", re.I | re.M),
    re.compile(r"\[INST\]|\[/INST\]|</?s>", re.I),
    re.compile(r"__import__\s*\(", re.I),
    re.compile(r"\beval\s*\(", re.I),
    re.compile(r"\bexec\s*\(", re.I),
    re.compile(r"BEGIN\s+(RSA\s+|EC\s+|OPENSSH\s+|DSA\s+)?PRIVATE\s+KEY", re.I),
    re.compile(r"\$\{jndi:", re.I),
    re.compile(r"<%.*?system\s*\(.+?\).*?%>", re.I | re.S),
]


@dataclass(frozen=True)
class GuardResult:
    safe: bool
    reason: str | None = None
    pattern: str | None = None


class LLMGuardClient:
    """Sanitização heurística antes de toda chamada ao Claude."""

    def __init__(self, *, enabled: bool | None = None) -> None:
        self.enabled = settings.LLM_GUARD_ENABLED if enabled is None else enabled

    def check(self, text: str) -> GuardResult:
        if not self.enabled:
            return GuardResult(safe=True)
        if not text:
            return GuardResult(safe=True)
        for pattern in _INJECTION_PATTERNS:
            match = pattern.search(text)
            if match:
                logger.warning(
                    "llm_guard_blocked",
                    pattern=pattern.pattern,
                    match=match.group(0)[:80],
                )
                return GuardResult(
                    safe=False,
                    reason="prompt_injection_pattern",
                    pattern=pattern.pattern,
                )
        return GuardResult(safe=True)

    def sanitize_findings(self, findings: list[dict]) -> list[dict]:
        """Retorna apenas os findings cujo conteúdo passou no check.

        Útil porque payloads de injection chegam normalmente em
        campos ``description`` / ``raw_output`` de findings vindos de
        scanners — atacantes podem plantar comentários no código.
        """
        safe: list[dict] = []
        for f in findings:
            content = " ".join(
                str(f.get(k, "")) for k in ("title", "description")
            )
            if self.check(content).safe:
                safe.append(f)
        return safe
