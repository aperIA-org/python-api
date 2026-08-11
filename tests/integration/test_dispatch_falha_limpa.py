"""Falha de disparo não deixa scan fantasma no dashboard.

Regressão do incidente: o canvas é um chord e o ``current_app`` do Celery é
thread-local — nas rotas (que o FastAPI roda em threadpool) a checagem caía numa
app ``'default'`` sem backend e levantava ``NotImplementedError``. A linha do
``ScanJob`` já tinha sido gravada, então a API respondia 500 "não foi possível
iniciar o scan" **e** o scan aparecia em `/dash/scans` em execução.
"""
from unittest.mock import patch

import pytest

from app.core import orchestrator
from app.core.celery_app import celery_app
from app.core.exceptions import ScanDispatchError

ARGS = dict(
    commit_sha="e" * 40,
    repo_url="https://github.com/acme/repo",
    repo_full_name="acme/repo",
    installation_id=42,
    pr_number=None,
    base_sha="e" * 40,
    head_sha="e" * 40,
    changed_files=[],
)


def test_app_celery_e_default_global():
    """`set_default()` torna a app resolvível em QUALQUER thread."""
    import concurrent.futures

    def backend_em_outra_thread():
        from celery import current_app

        return current_app.main, type(current_app.backend).__name__

    with concurrent.futures.ThreadPoolExecutor(1) as ex:
        main, backend = ex.submit(backend_em_outra_thread).result()

    assert main == celery_app.main
    assert backend != "DisabledBackend"


def test_canvas_quebrado_nao_cria_scan_job():
    """Se o canvas nem monta, nenhuma linha deve nascer."""
    with patch.object(
        orchestrator, "build_pipeline_canvas", side_effect=RuntimeError("canvas ruim")
    ), patch.object(orchestrator, "_noop", create=True):
        with patch(
            "app.infrastructure.persistence.scan_job_writer.create_scan_job"
        ) as create:
            with pytest.raises(RuntimeError):
                orchestrator.start_pipeline(**ARGS)

    create.assert_not_called()


def test_falha_no_apply_async_encerra_os_tiers():
    """Se a linha já existe, ela não pode ficar `running` para sempre."""

    class _CanvasQuebrado:
        def apply_async(self):
            raise RuntimeError("broker fora do ar")

    with patch.object(
        orchestrator, "build_pipeline_canvas", return_value=_CanvasQuebrado()
    ), patch(
        "app.infrastructure.persistence.scan_job_writer.create_scan_job"
    ), patch(
        "app.infrastructure.persistence.scan_job_writer.fail_pending_tiers"
    ) as fail:
        with pytest.raises(ScanDispatchError) as exc_info:
            orchestrator.start_pipeline(**ARGS)

    fail.assert_called_once()
    assert fail.call_args[0][0] == "e" * 40
    # A causa original precisa sobreviver para quem for depurar.
    assert "broker fora do ar" in str(exc_info.value)
