"""Fixtures globais de teste.

Decisão #2 (Semana 6): teardown EXPLÍCITO do estado Celery para
evitar contaminação entre testes. Cada test function entra com
``task_always_eager=True`` e sai com a configuração original
restaurada — mesmo quando o teste falha.

Também limpa o estado do ``CircuitBreaker`` singleton compartilhado
para que falhas em um teste de AI não vazem para o próximo.
"""
from __future__ import annotations

import pytest

from app.core.celery_app import celery_app
from app.infrastructure.ai.circuit_breaker import (
    DEFAULT_BREAKER,
    CircuitState,
)


@pytest.fixture(autouse=True)
def celery_eager_mode():
    """Roda todas as tasks inline no processo do teste.

    Backend de resultados é trocado para ``cache+memory://`` — sem
    isso, canvas (chain/group/chord) tenta gravar resultados no
    Redis do ``CELERY_RESULT_BACKEND``, que não existe em ambiente
    de teste.

    Restaura todos os valores originais após cada teste — mesmo se
    o teste falhar (try/finally implícito no yield).
    """
    original_eager = celery_app.conf.task_always_eager
    original_propagates = celery_app.conf.task_eager_propagates
    original_backend = celery_app.conf.result_backend
    original_store_eager = celery_app.conf.task_store_eager_result

    celery_app.conf.task_always_eager = True
    celery_app.conf.task_eager_propagates = True
    celery_app.conf.result_backend = "cache+memory://"
    celery_app.conf.task_store_eager_result = True
    try:
        yield
    finally:
        celery_app.conf.task_always_eager = original_eager
        celery_app.conf.task_eager_propagates = original_propagates
        celery_app.conf.result_backend = original_backend
        celery_app.conf.task_store_eager_result = original_store_eager


@pytest.fixture(autouse=True)
def reset_circuit_breaker():
    """Garante que cada teste começa com o breaker singleton em CLOSED."""
    DEFAULT_BREAKER._failures = 0
    DEFAULT_BREAKER._state = CircuitState.CLOSED
    DEFAULT_BREAKER._opened_at = 0.0
    yield
    DEFAULT_BREAKER._failures = 0
    DEFAULT_BREAKER._state = CircuitState.CLOSED
    DEFAULT_BREAKER._opened_at = 0.0
