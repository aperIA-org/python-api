"""Quais ferramentas cada tier executa.

Uma lista, um lugar. Ela é a fonte para dois usos que precisam concordar:

- os gates, que marcam como ``skipped`` **todas** as ferramentas de um tier que
  não vai rodar (sem isso, um tier pulado simplesmente não teria linha, e "não
  rodou" ficaria indistinguível de "ainda não chegou aqui");
- a rota ``GET /scans/{id}/tools``, que precisa saber o conjunto esperado para
  a UI listar as ferramentas de um tier que ainda nem começou.

Os identificadores são estáveis e fazem parte do contrato com o front — o
Semgrep aparece duas vezes porque roda em dois tiers com escopos diferentes, e
são duas ferramentas do ponto de vista de quem lê o pipeline.
"""
from __future__ import annotations

TIER_TOOLS: dict[int, tuple[str, ...]] = {
    1: ("trufflehog", "semgrep-changed"),
    2: ("trivy", "semgrep-full", "prowler", "ia-tier2"),
    3: ("zap", "threat-intel", "caldera", "ia-tier3"),
}

# Todos os ids válidos, para validação e para a ordem de exibição.
ALL_TOOLS: tuple[str, ...] = tuple(
    tool for tier in sorted(TIER_TOOLS) for tool in TIER_TOOLS[tier]
)


def tier_of(tool: str) -> int | None:
    """Tier a que uma ferramenta pertence, ou ``None`` se o id é desconhecido."""
    for tier, tools in TIER_TOOLS.items():
        if tool in tools:
            return tier
    return None
