"""Testes de integração dos workers Celery (Tier 1 + Analysis + Reporting).

Modo eager ativado via ``conftest.py``. Dependências externas são
mockadas por ``unittest.mock.patch`` no namespace do módulo do worker
— Celery não serializa MagicMock pelo broker JSON, então não
passamos clients como kwargs.

Sobre ``Ignore`` em modo eager: o Celery captura ``Ignore`` no
``apply()`` interno (eager) e marca o ``EagerResult`` como
state=IGNORED — NÃO levanta a exceção para o caller. Por isso os
testes de Gate 1 verificam (a) side effects (GitHubClient chamado
com state="failure") e (b) state do resultado.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from app.domain.finding.entities import Finding
from app.domain.finding.value_objects import Severity
from app.presentation.workers import (
    analysis_worker,
    reporting_worker,
    tier1_scan_worker,
)


def _make_finding(**overrides) -> Finding:
    base = {
        "source": "semgrep",
        "severity": Severity.HIGH,
        "title": "SQL injection",
        "description": "x",
        "commit_sha": "a" * 40,
        "repo_url": "https://github.com/acme/repo",
        "file_path": "app/db.py",
        "line_number": 42,
    }
    base.update(overrides)
    return Finding(**base)


# -----------------------------------------------------------------------------
# Tier 1 workers
# -----------------------------------------------------------------------------


class TestTier1ScanWorker:
    def test_run_trufflehog_serializes_findings(self):
        verified = _make_finding(
            source="trufflehog",
            severity=Severity.CRITICAL,
            secret_verified=True,
            secret_type="AWS",
        )
        with patch(
            "app.presentation.workers.tier1_scan_worker.TruffleHogScanner"
        ) as MockScanner:
            instance = MockScanner.return_value
            instance.run_safe.return_value = [verified]
            result = tier1_scan_worker.run_trufflehog.delay(
                repo_full_name="acme/repo",
                installation_id=42,
                base_sha="x",
                head_sha="y",
                commit_sha="a" * 40,
                repo_url="https://github.com/x/y",
            ).get()

        assert len(result) == 1
        assert isinstance(result[0], dict)
        assert result[0]["secret_verified"] is True
        assert result[0]["secret_type"] == "AWS"
        assert result[0]["severity"] == "critical"

    def test_run_semgrep_changed_propagates_kwargs(self):
        finding = _make_finding()
        with patch(
            "app.presentation.workers.tier1_scan_worker.SemgrepScanner"
        ) as MockScanner:
            instance = MockScanner.return_value
            instance.run_safe.return_value = [finding]
            tier1_scan_worker.run_semgrep_changed.delay(
                repo_full_name="acme/repo",
                installation_id=42,
                changed_files=["a.py", "b.py"],
                commit_sha="a" * 40,
                repo_url="https://github.com/x/y",
            ).get()
            instance.run_safe.assert_called_once()
            kwargs = instance.run_safe.call_args.kwargs
            assert kwargs["changed_files"] == ["a.py", "b.py"]

    def test_scanner_exception_yields_empty_list(self):
        with patch(
            "app.presentation.workers.tier1_scan_worker.TruffleHogScanner"
        ) as MockScanner:
            instance = MockScanner.return_value
            instance.run_safe.return_value = []
            result = tier1_scan_worker.run_trufflehog.delay(
                repo_full_name="acme/repo",
                installation_id=42,
                base_sha="x",
                head_sha="y",
                commit_sha="a" * 40,
                repo_url="https://github.com/x/y",
            ).get()
        assert result == []


# -----------------------------------------------------------------------------
# Analysis worker — Gate 1
# -----------------------------------------------------------------------------


class TestGate1:
    @pytest.fixture
    def mock_github(self):
        with patch(
            "app.presentation.workers.analysis_worker.GitHubClient"
        ) as MockClient:
            yield MockClient.return_value

    def test_gate1_blocks_when_verified_secret_present(self, mock_github):
        tier1_results = [
            [
                {
                    "secret_verified": True,
                    "severity": "critical",
                    "source": "trufflehog",
                    "secret_type": "AWS",
                }
            ],
            [],
        ]
        ar = analysis_worker.gate1_check.delay(
            tier1_results,
            repo_full_name="acme/repo",
            pr_number=7,
            commit_sha="a" * 40,
            installation_id=42,
        )
        # Celery transforma raise Ignore() em state IGNORED no EagerResult.
        # O importante é o side effect: status check + comment foram criados.
        assert ar.state == "IGNORED"
        mock_github.create_status_check.assert_called_once()
        mock_github.post_pr_comment.assert_called_once()
        status_kwargs = mock_github.create_status_check.call_args.kwargs
        assert status_kwargs["state"] == "failure"
        assert "secret" in status_kwargs["description"].lower()

    def test_gate1_passes_when_no_verified_secret(self, mock_github):
        tier1_results = [
            [
                {
                    "secret_verified": False,
                    "severity": "high",
                    "source": "semgrep",
                    "title": "SQL injection",
                }
            ],
            [],
        ]
        result = analysis_worker.gate1_check.delay(
            tier1_results,
            repo_full_name="acme/repo",
            pr_number=7,
            commit_sha="a" * 40,
            installation_id=42,
        ).get()
        assert result["blocked"] is False
        assert len(result["findings"]) == 1
        mock_github.create_status_check.assert_not_called()
        mock_github.post_pr_comment.assert_not_called()

    def test_gate1_aggregates_findings_from_multiple_tier1_lists(self, mock_github):
        result = analysis_worker.gate1_check.delay(
            [[{"title": "a"}], [{"title": "b"}], [{"title": "c"}]],
            repo_full_name="acme/repo",
            pr_number=1,
            commit_sha="a" * 40,
            installation_id=1,
        ).get()
        assert len(result["findings"]) == 3

    def test_gate1_sem_pr_number_cria_status_check_mas_nao_comenta(self, mock_github):
        """Scan manual: o status check é no commit (existe), o comentário não."""
        ar = analysis_worker.gate1_check.delay(
            [[{"secret_verified": True, "source": "trufflehog"}]],
            repo_full_name="acme/repo",
            pr_number=None,
            commit_sha="a" * 40,
            installation_id=42,
        )
        assert ar.state == "IGNORED"
        mock_github.create_status_check.assert_called_once()
        mock_github.post_pr_comment.assert_not_called()

    def test_gate1_blocks_even_when_github_post_fails(self, mock_github):
        mock_github.create_status_check.side_effect = RuntimeError("403")
        ar = analysis_worker.gate1_check.delay(
            [[{"secret_verified": True}]],
            repo_full_name="acme/repo",
            pr_number=1,
            commit_sha="a" * 40,
            installation_id=1,
        )
        # Mesmo com GitHub falhando, o pipeline é interrompido (IGNORED).
        assert ar.state == "IGNORED"


class TestGate1PersisteOBloqueio:
    """Bloqueio do Gate 1 é decisão: T2 e T3 nunca vão rodar neste commit.

    Deixá-los ``NULL`` faz a API/dashboard mostrar o mesmo traço de "ainda não
    chegou nesse tier".
    """

    @pytest.fixture
    def mock_github(self):
        with patch(
            "app.presentation.workers.analysis_worker.GitHubClient"
        ) as MockClient:
            yield MockClient.return_value

    @pytest.fixture
    def persistence_on(self):
        from sqlalchemy import create_engine
        from sqlalchemy.orm import sessionmaker
        from sqlalchemy.pool import StaticPool

        from app.config import settings
        from app.infrastructure.persistence import scan_job_writer
        from app.infrastructure.persistence.models import (  # noqa: F401 — bind metadata
            finding_model,
            refresh_token_model,
            remediation_model,
            scan_job_model,
            user_model,
        )
        from app.infrastructure.persistence.models.base import Base

        eng = create_engine(
            "sqlite://",
            connect_args={"check_same_thread": False},
            poolclass=StaticPool,
            future=True,
        )
        Base.metadata.create_all(eng)
        factory = sessionmaker(bind=eng, expire_on_commit=False, autoflush=False)
        original = settings.SCAN_PERSISTENCE_ENABLED
        settings.SCAN_PERSISTENCE_ENABLED = True
        with patch.object(scan_job_writer, "SessionLocal", factory):
            scan_job_writer.create_scan_job(
                commit_sha="a" * 40,
                repo_url="https://github.com/acme/repo",
                installation_id=1,
            )
            yield factory
        settings.SCAN_PERSISTENCE_ENABLED = original
        eng.dispose()

    def test_bloqueio_marca_t1_done_e_t2_t3_skipped(self, mock_github, persistence_on):
        from app.domain.scan.value_objects import ScanTier, TierStatus
        from app.infrastructure.repositories.sqlalchemy_scan_job_repository import (
            SQLAlchemyScanJobRepository,
        )

        ar = analysis_worker.gate1_check.delay(
            [[{"secret_verified": True, "source": "trufflehog"}]],
            repo_full_name="acme/repo",
            pr_number=7,
            commit_sha="a" * 40,
            installation_id=1,
        )
        assert ar.state == "IGNORED"

        with persistence_on() as s:
            job = SQLAlchemyScanJobRepository(s).get_by_commit("a" * 40)
        assert job.tier1_status == TierStatus.DONE
        assert job.blocked_at_tier is ScanTier.ONE
        assert job.tier2_status == TierStatus.SKIPPED
        assert job.tier3_status == TierStatus.SKIPPED


# -----------------------------------------------------------------------------
# Analysis worker — Tier 2 (Claude)
# -----------------------------------------------------------------------------


@pytest.fixture
def patched_analysis_claude():
    """Patcheia ClaudeClient no namespace do analysis_worker.

    Retorna a instância mockada que os testes podem configurar.
    """
    with patch(
        "app.presentation.workers.analysis_worker.ClaudeClient"
    ) as MockClass:
        yield MockClass.return_value


class TestTier2Analyze:
    def test_claude_call_uses_chain_of_events_prompt(self, patched_analysis_claude):
        patched_analysis_claude.call_json.return_value = {
            "event_chain": [],
            "risk_score": {"score": 30, "level": "low"},
            "business_impact": {"description": "x", "estimated_cost_brl": None},
            "attack_narrative": "...",
        }
        result = analysis_worker.tier2_analyze.delay(
            {"findings": [{"severity": "high", "source": "semgrep", "title": "x"}]},
            commit_sha="a" * 40,
        ).get()
        assert result["degraded"] is False
        assert result["risk_score"]["score"] == 30
        kwargs = patched_analysis_claude.call_json.call_args.kwargs
        assert "Findings (1)" in kwargs["user"]
        # CTI e Caldera são do Tier 3: o prompt do Tier 2 não carrega nem os
        # blocos nem o antigo "sem dados disponíveis".
        assert "CTI" not in kwargs["user"]
        assert "Caldera" not in kwargs["user"]

    def test_payload_carrega_o_commit_para_o_gate2(self, patched_analysis_claude):
        """O Gate 2 só recebe este dict — sem a chave ele fica sem identidade."""
        patched_analysis_claude.call_json.return_value = {
            "event_chain": [],
            "risk_score": {"score": 0, "level": "info"},
        }
        result = analysis_worker.tier2_analyze.delay(
            {"findings": []},
            commit_sha="a" * 40,
        ).get()
        assert result["commit_sha"] == "a" * 40

    def test_payload_degradado_tambem_carrega_o_commit(self, patched_analysis_claude):
        from app.infrastructure.ai.claude_client import CircuitOpenError

        patched_analysis_claude.call_json.side_effect = CircuitOpenError("open")
        result = analysis_worker.tier2_analyze.delay(
            {"findings": []},
            commit_sha="a" * 40,
        ).get()
        assert result["commit_sha"] == "a" * 40

    def test_circuit_open_yields_degraded_response(self, patched_analysis_claude):
        from app.infrastructure.ai.claude_client import CircuitOpenError

        patched_analysis_claude.call_json.side_effect = CircuitOpenError("open")
        result = analysis_worker.tier2_analyze.delay(
            {"findings": [{"severity": "high", "source": "semgrep"}]},
            commit_sha="a" * 40,
        ).get()
        assert result["degraded"] is True
        assert result["reason"] == "CircuitOpenError"
        assert len(result["findings"]) == 1

    def test_guard_blocked_yields_degraded_response(self, patched_analysis_claude):
        from app.infrastructure.ai.claude_client import GuardBlockedError

        patched_analysis_claude.call_json.side_effect = GuardBlockedError("injection")
        result = analysis_worker.tier2_analyze.delay(
            {"findings": []},
            commit_sha="a" * 40,
        ).get()
        assert result["degraded"] is True
        assert result["reason"] == "GuardBlockedError"

    def test_resultado_nao_carrega_status_de_inteligencia(
        self, patched_analysis_claude
    ):
        """O Tier 2 não injeta mais `cti_status`/`caldera_status`.

        Substitui `test_empty_cti_caldera_still_works`: os dois eram sempre
        `unavailable` porque CTI e Caldera rodam no Tier 3 — o relatório fechava
        com um rodapé fixo que parecia falha e era só ausência de tentativa.
        """
        patched_analysis_claude.call_json.return_value = {
            "event_chain": [],
            "risk_score": {"score": 0, "level": "info"},
            "business_impact": {"description": ""},
            "attack_narrative": "",
        }
        result = analysis_worker.tier2_analyze.delay(
            {"findings": []},
            commit_sha="a" * 40,
        ).get()
        assert result["degraded"] is False
        assert "cti_status" not in result
        assert "caldera_status" not in result

    def test_payload_degradado_tambem_nao_carrega_status_de_inteligencia(
        self, patched_analysis_claude
    ):
        """O caminho degradado montava o dict à mão e também injetava os dois."""
        from app.infrastructure.ai.claude_client import CircuitOpenError

        patched_analysis_claude.call_json.side_effect = CircuitOpenError("open")
        result = analysis_worker.tier2_analyze.delay(
            {"findings": []},
            commit_sha="a" * 40,
        ).get()
        assert result["degraded"] is True
        assert "cti_status" not in result
        assert "caldera_status" not in result

    def test_tier2_analyze_recusa_cti_e_caldera_como_kwargs(
        self, patched_analysis_claude
    ):
        """Lock da assinatura: um chamador que ainda passe os dados do Tier 3
        deve falhar alto, não ser ignorado em silêncio."""
        with pytest.raises(TypeError):
            analysis_worker.tier2_analyze.delay(
                {"findings": []},
                commit_sha="a" * 40,
                cti_data={},
            )
        with pytest.raises(TypeError):
            analysis_worker.tier2_analyze.delay(
                {"findings": []},
                commit_sha="a" * 40,
                caldera_results={},
            )


# -----------------------------------------------------------------------------
# Reporting worker
# -----------------------------------------------------------------------------


@pytest.fixture
def patched_reporting_claude():
    with patch(
        "app.presentation.workers.reporting_worker.ClaudeClient"
    ) as MockClass:
        yield MockClass.return_value


@pytest.fixture
def patched_reporting_github():
    with patch(
        "app.presentation.workers.reporting_worker.GitHubClient"
    ) as MockClass:
        yield MockClass.return_value


class TestReportingWorker:
    def test_posts_claude_generated_report(
        self, patched_reporting_claude, patched_reporting_github
    ):
        patched_reporting_claude.call.return_value = MagicMock(text="## Report markdown")
        patched_reporting_github.post_pr_comment.return_value = 999

        result = reporting_worker.post_tier2_report.delay(
            {
                "degraded": False,
                "risk_score": {"score": 50, "level": "medium"},
                "event_chain": [],
                "business_impact": {"description": "x"},
                "attack_narrative": "...",
            },
            repo_full_name="acme/repo",
            pr_number=7,
            commit_sha="a" * 40,
            installation_id=42,
        ).get()
        assert result["_post_meta"]["posted"] is True
        assert result["_post_meta"]["comment_id"] == 999
        # Pipeline-flow: a análise foi preservada intacta no retorno
        assert result["risk_score"]["score"] == 50
        body = patched_reporting_github.post_pr_comment.call_args.kwargs["body"]
        assert "Report markdown" in body

    def test_degraded_analysis_uses_fallback_markdown(
        self, patched_reporting_claude, patched_reporting_github
    ):
        patched_reporting_github.post_pr_comment.return_value = 1
        result = reporting_worker.post_tier2_report.delay(
            {
                "degraded": True,
                "reason": "CircuitOpenError",
                "findings": [
                    {
                        "severity": "high",
                        "source": "semgrep",
                        "title": "SQL injection",
                        "file_path": "app/db.py",
                        "line_number": 42,
                    }
                ],
            },
            repo_full_name="acme/repo",
            pr_number=7,
            commit_sha="a" * 40,
            installation_id=42,
        ).get()
        assert result["_post_meta"]["posted"] is True
        patched_reporting_claude.call.assert_not_called()
        body = patched_reporting_github.post_pr_comment.call_args.kwargs["body"]
        assert "modo degradado" in body
        assert "SQL injection" in body

    def test_claude_failure_falls_back_to_raw_listing(
        self, patched_reporting_claude, patched_reporting_github
    ):
        from app.infrastructure.ai.claude_client import CircuitOpenError

        patched_reporting_claude.call.side_effect = CircuitOpenError("open")
        patched_reporting_github.post_pr_comment.return_value = 1
        result = reporting_worker.post_tier2_report.delay(
            {
                "degraded": False,
                "findings": [
                    {"severity": "low", "source": "semgrep", "title": "x"}
                ],
                "risk_score": {"score": 20, "level": "low"},
                "event_chain": [],
                "business_impact": {},
                "attack_narrative": "",
            },
            repo_full_name="acme/repo",
            pr_number=7,
            commit_sha="a" * 40,
            installation_id=42,
        ).get()
        assert result["_post_meta"]["posted"] is True
        body = patched_reporting_github.post_pr_comment.call_args.kwargs["body"]
        assert "modo degradado" in body

    def test_github_post_failure_returns_posted_false(
        self, patched_reporting_claude, patched_reporting_github
    ):
        patched_reporting_claude.call.return_value = MagicMock(text="ok")
        patched_reporting_github.post_pr_comment.side_effect = RuntimeError("403")
        result = reporting_worker.post_tier2_report.delay(
            {
                "degraded": False,
                "risk_score": {"score": 50, "level": "medium"},
                "event_chain": [],
                "business_impact": {},
                "attack_narrative": "",
            },
            repo_full_name="acme/repo",
            pr_number=7,
            commit_sha="a" * 40,
            installation_id=42,
        ).get()
        assert result["_post_meta"]["posted"] is False
        assert "403" in result["_post_meta"]["error"]

    def test_sem_pr_number_nao_comenta_no_github(
        self, patched_reporting_claude, patched_reporting_github
    ):
        """Scan manual (de branch): não há PR — o post é pulado, não tentado."""
        patched_reporting_claude.call.return_value = MagicMock(text="## Report")
        result = reporting_worker.post_tier2_report.delay(
            {
                "degraded": False,
                "risk_score": {"score": 50, "level": "medium"},
                "event_chain": [],
                "business_impact": {},
                "attack_narrative": "",
            },
            repo_full_name="acme/repo",
            pr_number=None,
            commit_sha="a" * 40,
            installation_id=42,
        ).get()
        assert result["_post_meta"] == {"posted": False, "reason": "sem_pr"}
        patched_reporting_github.post_pr_comment.assert_not_called()


# -----------------------------------------------------------------------------
# Validação de Celery boot (decisão #3 da Semana 6)
# -----------------------------------------------------------------------------


class TestCeleryBoot:
    def test_all_workers_registered(self):
        from app.core.celery_app import celery_app

        expected = {
            "app.presentation.workers.tier1_scan_worker.run_trufflehog",
            "app.presentation.workers.tier1_scan_worker.run_semgrep_changed",
            "app.presentation.workers.analysis_worker.gate1_check",
            "app.presentation.workers.analysis_worker.tier2_analyze",
            "app.presentation.workers.reporting_worker.post_tier2_report",
        }
        registered = set(celery_app.tasks.keys())
        missing = expected - registered
        assert not missing, f"Tasks ausentes do registry: {missing}"

    def test_routes_isolate_tiers(self):
        from app.core.celery_app import celery_app

        routes = celery_app.conf.task_routes
        assert routes["app.presentation.workers.tier1_scan_worker.*"]["queue"] == "tier1"
        assert routes["app.presentation.workers.analysis_worker.*"]["queue"] == "analysis"
        assert routes["app.presentation.workers.reporting_worker.*"]["queue"] == "reporting"

    def test_acks_late_and_no_pickle(self):
        from app.core.celery_app import celery_app

        assert celery_app.conf.task_acks_late is True
        assert celery_app.conf.task_serializer == "json"
        assert "pickle" not in celery_app.conf.accept_content

    def test_import_validation_passes(self):
        """Decisão #3: import manual dos workers funciona."""
        from app.core.celery_app import WORKER_MODULES, _validate_worker_imports

        # Não deve levantar — todos os módulos importam limpos.
        _validate_worker_imports(WORKER_MODULES)
