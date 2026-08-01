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



# Material sensível que um scanner de secrets legitimamente encontra e reporta.
# Redigido ANTES de compor o prompt: o modelo não precisa do segredo em si para
# raciocinar sobre ele — precisa saber que existe, de que tipo e onde.
_SEGREDOS_A_REDIGIR = [
    # Bloco PEM completo (com END) ou truncado (só o header + corpo base64).
    (
        re.compile(
            r"-{2,}\s*BEGIN\s+(?:RSA\s+|EC\s+|OPENSSH\s+|DSA\s+|PGP\s+)?PRIVATE\s+KEY"
            r"[\s\S]*?(?:-{2,}\s*END\s+(?:RSA\s+|EC\s+|OPENSSH\s+|DSA\s+|PGP\s+)?"
            r"PRIVATE\s+KEY\s*-{2,}|$)",
            re.I,
        ),
        "[chave privada redigida pelo aperIA]",
    ),
]


def redigir_segredos(texto: str) -> tuple[str, int]:
    """Substitui material de segredo por marcador. Devolve (texto, nº de trocas).

    Existe porque a guarda anti-prompt-injection e o produto se atropelavam: o
    padrão ``BEGIN ... PRIVATE KEY`` é, ao mesmo tempo, um vetor conhecido de
    injection **e** exatamente aquilo que um scanner de secrets deve achar. Com
    o Juice Shop — que tem uma chave privada real no repositório — a guarda
    bloqueava a chamada e o Tier 2 caía em modo degradado. Ou seja: quanto
    melhor o scanner trabalhava, menos análise por IA o usuário recebia.

    Redigir resolve os dois lados de uma vez. O segredo **não sai** da
    infraestrutura (mandar uma chave privada real para um LLM de terceiros é
    indesejável por si só), e o texto que sobra não dispara a guarda. O valor
    original continua no banco e em ``raw_output`` — quem precisa dele é o
    usuário, não o modelo.
    """
    trocas = 0
    for padrao, marcador in _SEGREDOS_A_REDIGIR:
        texto, n = padrao.subn(marcador, texto)
        trocas += n
    return texto, trocas


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
