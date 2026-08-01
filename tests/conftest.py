"""Fixtures globais de teste.

Decisão #2 (Semana 6): teardown EXPLÍCITO do estado Celery para
evitar contaminação entre testes. Cada test function entra com
``task_always_eager=True`` e sai com a configuração original
restaurada — mesmo quando o teste falha.

Também limpa o estado do ``CircuitBreaker`` singleton compartilhado
para que falhas em um teste de AI não vazem para o próximo.
"""
from __future__ import annotations

import shutil
import tempfile
from contextlib import contextmanager
from unittest.mock import patch

import pytest

from app.config import settings
from app.core.celery_app import celery_app
from app.infrastructure.ai.circuit_breaker import (
    DEFAULT_BREAKER,
    CircuitState,
)


@pytest.fixture(autouse=True)
def disable_findings_persistence():
    """Desliga a persistência best-effort de findings por padrão.

    Os scan workers gravam no banco via ``SessionLocal`` (Postgres). Em
    teste não há banco — desligamos globalmente para os testes de worker
    não tentarem conectar. Os testes que exercitam a persistência ligam
    o flag explicitamente e injetam uma Session sqlite.
    """
    original = settings.FINDINGS_PERSISTENCE_ENABLED
    settings.FINDINGS_PERSISTENCE_ENABLED = False
    try:
        yield
    finally:
        settings.FINDINGS_PERSISTENCE_ENABLED = original


@pytest.fixture(autouse=True)
def alvo_interno_bloqueado_por_padrao():
    """Força a postura de PRODUÇÃO na validação de alvo de DAST.

    ``ALLOW_INTERNAL_DAST_TARGETS`` é uma flag de desenvolvimento: sem ela não
    há como apontar a ``target_url`` para um Juice Shop local
    (``http://juice-shop:3000``), que é exatamente o que a proteção anti-SSRF
    recusa.

    O problema é que ``settings`` lê o ``.env`` do desenvolvedor. Com a flag
    ligada localmente, os 13 testes que provam a recusa de alvo interno
    (loopback, RFC1918, metadata de cloud) passavam a falhar — ou, pior, num
    cenário invertido, passariam a "passar" sem testar nada.

    Um flag local não pode decidir se os testes de segurança rodam. O padrão
    aqui é sempre ``False``; quem exercita a liberação passa
    ``permitir_alvo_interno=True`` explicitamente ou religa o setting.
    """
    original = settings.ALLOW_INTERNAL_DAST_TARGETS
    settings.ALLOW_INTERNAL_DAST_TARGETS = False
    try:
        yield
    finally:
        settings.ALLOW_INTERNAL_DAST_TARGETS = original


@pytest.fixture(autouse=True)
def disable_scan_persistence():
    """Desliga a persistência best-effort do ScanJob por padrão.

    Mesmo racional do ``disable_findings_persistence``: os workers/orquestrador
    gravam o ciclo de vida do ScanJob via ``SessionLocal`` (Postgres). Em teste
    não há banco — desligamos globalmente. Os testes que exercitam a persistência
    religam o flag e injetam uma Session sqlite.
    """
    original = settings.SCAN_PERSISTENCE_ENABLED
    settings.SCAN_PERSISTENCE_ENABLED = False
    try:
        yield
    finally:
        settings.SCAN_PERSISTENCE_ENABLED = original


@pytest.fixture(autouse=True)
def fake_repo_checkout():
    """Neutraliza o checkout real do repositório nos scan workers.

    Os workers de T1/T2 clonam o commit antes de rodar os scanners. Em teste
    não há GitHub App, token nem rede — trocamos o clone por um diretório
    temporário vazio (criado e apagado igual ao real, para que qualquer código
    que dependa da existência do caminho continue válido).

    O patch é só na referência que o ``checkout_guard`` importou: os testes do
    próprio checkout usam ``infrastructure.git.repo_checkout`` direto e não são
    afetados. Testes que precisam simular falha de checkout sobrescrevem este
    patch localmente.
    """
    from app.presentation.workers import checkout_guard

    @contextmanager
    def _checkout_falso(**_kwargs):
        destino = tempfile.mkdtemp(prefix="aperia-test-checkout-")
        try:
            yield destino
        finally:
            shutil.rmtree(destino, ignore_errors=True)

    with patch.object(checkout_guard, "checkout_repo", _checkout_falso):
        yield


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
