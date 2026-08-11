"""Celery app aperIA.

Decisões operacionais:

- **Broker default**: ``settings.REDIS_URL`` aponta para o hostname do
  container (``redis://redis:6379/0``). Localhost só é usado quando o
  ``.env`` sobrescreve — evita surpresa em produção se alguém esquecer
  de definir a variável.
- **task_acks_late=True**: a task só é removida da fila depois de
  concluída. Se o worker crashar no meio, o broker reenvia. Custo:
  algumas tasks podem rodar duas vezes — todas devem ser idempotentes.
- **Filas por tier**: T1 (caminho crítico ≤ 3 min) tem prioridade
  natural por ser fila própria. T3 lento não bloqueia T1.
- **Validação de import antes de autodiscover**: chamamos
  ``importlib.import_module`` manualmente para cada worker. Se
  algum quebrar, falha cedo com mensagem clara — em vez do erro
  obscuro do autodiscover do Celery em runtime.
"""
from __future__ import annotations

import importlib
from typing import Iterable

import structlog
from celery import Celery

from app.config import settings

logger = structlog.get_logger()

# Módulos que precisam ser importáveis pelo Celery para registrar tasks.
# A ordem é relevante apenas para logs — todos são validados.
# ``app.core.orchestrator`` entra por ÚLTIMO: ele importa os 5 workers
# acima + o ``celery_app`` (já criado neste ponto), e define as tasks de
# bridge (`_t1_to_t2_scan_bridge` etc.). Sem registrá-lo nos workers, a
# chain morre ao chegar no primeiro bridge ("unregistered task").
WORKER_MODULES: tuple[str, ...] = (
    "app.presentation.workers.tier1_scan_worker",
    "app.presentation.workers.tier2_scan_worker",
    "app.presentation.workers.tier3_scan_worker",
    "app.presentation.workers.analysis_worker",
    "app.presentation.workers.reporting_worker",
    "app.core.orchestrator",
)


def _validate_worker_imports(modules: Iterable[str]) -> None:
    """Importa cada módulo de worker para falhar cedo com mensagem clara.

    O autodiscover do Celery silencia erros de import em alguns
    cenários, deixando tasks "registradas mas inexistentes". Esta
    validação pega o problema no boot do worker — antes de qualquer
    PR webhook chegar.
    """
    for module in modules:
        try:
            importlib.import_module(module)
        except ImportError as exc:
            raise ImportError(
                f"Worker module {module!r} não importou. "
                f"Verifique que (a) o arquivo existe, "
                f"(b) o pacote tem __init__.py em todos os níveis, "
                f"(c) não há erro de sintaxe. Erro original: {exc}"
            ) from exc
        logger.debug("worker_module_imported", module=module)


def _build_celery_app() -> Celery:
    broker_url = settings.CELERY_BROKER_URL or settings.REDIS_URL
    result_backend = settings.CELERY_RESULT_BACKEND or settings.REDIS_URL

    # NOTE: NÃO passamos ``include=`` aqui porque os módulos de worker
    # importam ``celery_app`` de volta — passar ``include`` força o
    # Celery a importá-los durante ``Celery.__init__``, gerando
    # circular import. Fazemos o import manual depois (ver fim do
    # módulo), o que valida importabilidade E registra as tasks.
    app = Celery(
        "aperia",
        broker=broker_url,
        backend=result_backend,
    )

    app.conf.update(
        # Idempotência e resiliência
        task_acks_late=True,
        task_reject_on_worker_lost=True,
        # Serialização — só JSON (sem pickle, que é vetor de RCE)
        task_serializer="json",
        result_serializer="json",
        accept_content=["json"],
        # Visibilidade no Flower / logs
        task_send_sent_event=True,
        worker_send_task_events=True,
        # Filas por tier.
        # IMPORTANTE: o argumento ``queue=`` no decorator ``@celery_app.task``
        # NÃO é honrado pelo router do Celery — roteamento vem daqui (ou de
        # ``apply_async(queue=...)``). As tasks de bridge do orquestrador
        # precisam de rotas explícitas, senão caem na fila default ``celery``,
        # que nenhum worker consome, e o pipeline trava após o Gate 1.
        task_routes={
            "app.presentation.workers.tier1_scan_worker.*": {"queue": "tier1"},
            "app.presentation.workers.analysis_worker.*": {"queue": "analysis"},
            "app.presentation.workers.reporting_worker.*": {"queue": "reporting"},
            "app.presentation.workers.tier2_scan_worker.*": {"queue": "tier2"},
            "app.presentation.workers.tier3_scan_worker.*": {"queue": "tier3"},
            "app.core.orchestrator._t1_to_t2_scan_bridge": {"queue": "tier2"},
            "app.core.orchestrator._bridge_t1_findings_into_analyze": {"queue": "analysis"},
            "app.core.orchestrator._prepare_tier3_payload": {"queue": "tier3"},
            "app.core.orchestrator._deep_analysis_bridge": {"queue": "analysis"},
        },
        # Modo eager (testes)
        task_always_eager=settings.CELERY_TASK_ALWAYS_EAGER,
        task_eager_propagates=settings.CELERY_TASK_EAGER_PROPAGATES,
        # Limites — T1 = 3 min, T2 = 10 min, T3 = 60 min
        task_time_limit=3600,
        task_soft_time_limit=3300,
    )
    return app


# Cria o app primeiro — workers importam ``celery_app`` deste módulo.
celery_app = _build_celery_app()

# ``set_default()`` NÃO é decorativo: sem ele o disparo falha em produção.
#
# O ``current_app`` do Celery é **thread-local**. Criar a app marca-a como
# corrente apenas na thread que executou este módulo (a principal). Numa outra
# thread o Celery fabrica silenciosamente uma app ``'default'`` — com
# ``DisabledBackend``, porque não tem configuração nenhuma.
#
# Isso morde o processo da API: as rotas são ``def`` (não ``async def``), então
# o FastAPI as executa num threadpool. O canvas do pipeline é um chord
# (``group | task``), e ``chord`` exige result backend — na thread errada a
# checagem cai na app ``'default'`` e levanta
# ``NotImplementedError: Starting chords requires a result backend``.
#
# O sintoma era intermitente e enganoso: funcionava na thread que por acaso
# tivesse importado a app primeiro, e falhava nas demais. Pior, a linha do
# ``ScanJob`` já tinha sido gravada quando o erro estourava, então o scan
# aparecia no dashboard "em execução" enquanto a API devolvia 500.
#
# ``set_default()`` registra a app como fallback GLOBAL, válido em qualquer
# thread. Os workers não dependiam disso (o Celery marca a app como corrente no
# boot do worker), o que ajudou a esconder o problema.
celery_app.set_default()

# Valida importabilidade DEPOIS do app existir. Pega problemas de
# packaging no boot (falta de ``__init__.py``, erro de sintaxe,
# import quebrado) — em vez do erro obscuro do autodiscover em
# runtime. O efeito colateral do import é registrar as tasks via
# decorador ``@celery_app.task``.
_validate_worker_imports(WORKER_MODULES)
