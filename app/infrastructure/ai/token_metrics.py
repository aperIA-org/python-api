"""Instrumentação Prometheus de tokens e custo USD da Claude API.

Por que custo em USD e não só tokens: o dashboard de negócio precisa
de algo acionável. "200k tokens" não comunica impacto; "$2.15 ontem"
sim.

Por que separar fresh/cache_read/cache_write: a Anthropic cobra
preços diferentes — ``input_tokens`` retornado pela API é o **total**
lido (inclui cache hits). Para custo correto, separar é obrigatório.
"""
from __future__ import annotations

from prometheus_client import Counter

from app.infrastructure.ai.models import pricing_for


# Nota: prometheus-client adiciona o sufixo "_total" automaticamente.
# Por isso o nome do Counter NÃO deve terminar em "_total" — caso
# contrário a métrica final fica "foo_total_total".
claude_tokens = Counter(
    "claude_tokens",
    "Tokens consumidos por modelo e tipo",
    ["model", "type"],
)

claude_cost_usd = Counter(
    "claude_cost_usd",
    "Custo acumulado em USD por modelo",
    ["model"],
)

claude_requests = Counter(
    "claude_requests",
    "Total de chamadas à Claude API por modelo e resultado",
    ["model", "outcome"],
)

# Aliases ergônomicos: os exportadores Prometheus geram samples com
# sufixo "_total". Para imports legados (token_metrics.claude_*_total)
# continuarmos compatíveis, mantemos referências.
claude_tokens_total = claude_tokens
claude_cost_usd_total = claude_cost_usd
claude_requests_total = claude_requests


def record_token_usage(
    *,
    model: str,
    input_tokens: int,
    cache_read_tokens: int,
    cache_write_tokens: int,
    output_tokens: int,
    commit_sha: str = "",
) -> None:
    pricing = pricing_for(model)
    if not pricing:
        return

    fresh_input = max(input_tokens - cache_read_tokens - cache_write_tokens, 0)

    cost = (
        (fresh_input / 1_000_000) * pricing.input
        + (cache_read_tokens / 1_000_000) * pricing.cache_read
        + (cache_write_tokens / 1_000_000) * pricing.cache_write
        + (output_tokens / 1_000_000) * pricing.output
    )

    claude_tokens.labels(model=model, type="input").inc(fresh_input)
    claude_tokens.labels(model=model, type="cache_read").inc(cache_read_tokens)
    claude_tokens.labels(model=model, type="cache_write").inc(cache_write_tokens)
    claude_tokens.labels(model=model, type="output").inc(output_tokens)
    claude_cost_usd.labels(model=model).inc(cost)


def record_request_outcome(model: str, outcome: str) -> None:
    """outcome: 'success' | 'circuit_open' | 'blocked_by_guard' | 'error'"""
    claude_requests.labels(model=model, outcome=outcome).inc()
