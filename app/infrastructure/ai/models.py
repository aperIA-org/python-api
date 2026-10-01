"""Constantes únicas para identificação de modelos Claude e pricing.

Princípio: nenhuma string literal de modelo Claude deve aparecer
fora deste módulo. Todo consumidor importa ``REASONING`` / ``FORMATTING``
ou consulta ``settings.CLAUDE_MODEL_*``.

Os valores reais vêm de ``app.config.settings`` para permitir override
via variável de ambiente (ex: testes, ambientes onde a Anthropic
renomeou o modelo).
"""
from __future__ import annotations

from dataclasses import dataclass

from app.config import settings


@dataclass(frozen=True)
class ModelPricing:
    """Custo por 1M de tokens em USD."""

    input: float
    output: float
    cache_read: float
    cache_write: float


REASONING: str = settings.CLAUDE_MODEL_REASONING
FORMATTING: str = settings.CLAUDE_MODEL_FORMATTING


# Mapa de modelo → preço. Sempre indexado pelas constantes acima,
# nunca por strings literais. Atualizar quando a Anthropic mudar
# o pricing.
PRICING: dict[str, ModelPricing] = {
    # Sonnet 5.5. Atenção ao trocar o modelo: estes números alimentam as
    # métricas de custo, e esquecê-los faz o painel mentir em silêncio.
    REASONING: ModelPricing(
        input=2.0,
        output=10.0,
        cache_read=0.20,
        cache_write=2.50,
    ),
    FORMATTING: ModelPricing(
        input=1.0,
        output=5.0,
        cache_read=0.10,
        cache_write=1.25,
    ),
}


def pricing_for(model: str) -> ModelPricing | None:
    """Retorna o pricing do modelo, ou ``None`` se desconhecido."""
    return PRICING.get(model)
