"""Testes do tier3_gate (Gate 2) — Semana 9.

Decisão #2: HIGH e CRITICAL escalam; INFO, LOW e MEDIUM encerram.
Decisão #3: skip == ``raise Ignore()``, nunca retornar dict.

Modo eager Celery do conftest converte ``Ignore`` em
``EagerResult.state == "IGNORED"`` — usamos isso para validar a
interrupção do chain.
"""
from __future__ import annotations

from celery.exceptions import Ignore

from unittest.mock import patch

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.config import settings
from app.domain.scan.value_objects import TierStatus
from app.infrastructure.persistence import scan_job_writer
from app.infrastructure.persistence.models import (  # noqa: F401 — bind metadata
    finding_model,
    refresh_token_model,
    remediation_model,
    scan_job_model,
    user_model,
)
from app.infrastructure.persistence.models.base import Base
from app.infrastructure.repositories.sqlalchemy_scan_job_repository import (
    SQLAlchemyScanJobRepository,
)
from app.presentation.workers import analysis_worker

SHA = "911a84b3" + "c" * 32


def _f(severity: str = "low", **overrides) -> dict:
    base = {
        "severity": severity,
        "source": "semgrep",
        "title": "x",
        "file_path": "app/x.py",
        "line_number": 1,
        "commit_sha": "a" * 40,
    }
    base.update(overrides)
    return base


def _analysis(findings: list[dict], **overrides) -> dict:
    base = {
        "findings": findings,
        "risk_score": {"score": 30, "level": "low"},
        "event_chain": [],
        "business_impact": {},
        "attack_narrative": "",
        "degraded": False,
    }
    base.update(overrides)
    return base


# -----------------------------------------------------------------------------
# Escala para Tier 3
# -----------------------------------------------------------------------------


class TestEscalation:
    def test_critical_finding_escalates(self):
        analysis = _analysis([_f(severity="critical")])
        result = analysis_worker.tier3_gate.delay(analysis).get()
        # Gate passa o dict inalterado para a próxima task no chain
        assert result == analysis

    def test_high_finding_escalates(self):
        analysis = _analysis([_f(severity="high")])
        result = analysis_worker.tier3_gate.delay(analysis).get()
        assert result == analysis

    def test_mixed_severities_escalate_on_max(self):
        analysis = _analysis(
            [
                _f(severity="info"),
                _f(severity="low"),
                _f(severity="high"),  # dispara escalação
            ]
        )
        result = analysis_worker.tier3_gate.delay(analysis).get()
        assert result == analysis

    def test_degraded_analysis_with_high_still_escalates(self):
        """Análise em modo degradado (Claude falhou) ainda escala se
        há risco real nos findings — não suprime decisão de segurança."""
        analysis = _analysis(
            [_f(severity="critical")],
            degraded=True,
            reason="CircuitOpenError",
        )
        result = analysis_worker.tier3_gate.delay(analysis).get()
        assert result == analysis


# -----------------------------------------------------------------------------
# Encerra no Tier 2 (Ignore)
# -----------------------------------------------------------------------------


class TestSkip:
    def test_low_only_skips_via_ignore(self):
        analysis = _analysis([_f(severity="low")])
        ar = analysis_worker.tier3_gate.delay(analysis)
        assert ar.state == "IGNORED"

    def test_info_only_skips(self):
        analysis = _analysis([_f(severity="info")])
        ar = analysis_worker.tier3_gate.delay(analysis)
        assert ar.state == "IGNORED"

    def test_medium_skips_per_threshold(self):
        """MEDIUM NÃO escala. Threshold conservador: só high/critical."""
        analysis = _analysis([_f(severity="medium")])
        ar = analysis_worker.tier3_gate.delay(analysis)
        assert ar.state == "IGNORED"

    def test_no_findings_skips(self):
        analysis = _analysis([])
        ar = analysis_worker.tier3_gate.delay(analysis)
        assert ar.state == "IGNORED"

    def test_skip_does_not_return_dict(self):
        """Decisão #3: skip nunca retorna dict — sempre Ignore.

        Verificamos via state IGNORED + ausência de payload no result.
        """
        analysis = _analysis([_f(severity="low")])
        ar = analysis_worker.tier3_gate.delay(analysis)
        assert ar.state == "IGNORED"
        # EagerResult em estado IGNORED não tem payload semântico
        # (o caller não deve usar o retorno para nada)
        assert ar.result is None or not isinstance(ar.result, dict) or not ar.result.get("findings")


# -----------------------------------------------------------------------------
# Severities case-insensitive e missing
# -----------------------------------------------------------------------------


class TestEdgeCases:
    def test_uppercase_severity_normalizes(self):
        analysis = _analysis([_f(severity="HIGH")])
        result = analysis_worker.tier3_gate.delay(analysis).get()
        assert result == analysis

    def test_missing_severity_treated_as_info(self):
        finding_without_sev = {"title": "x", "source": "semgrep"}
        analysis = _analysis([finding_without_sev])
        ar = analysis_worker.tier3_gate.delay(analysis)
        assert ar.state == "IGNORED"

    def test_unknown_severity_treated_as_lowest(self):
        analysis = _analysis([_f(severity="mystery")])
        ar = analysis_worker.tier3_gate.delay(analysis)
        assert ar.state == "IGNORED"


# -----------------------------------------------------------------------------
# Registro da task no Celery
# -----------------------------------------------------------------------------


class TestIdentidadeDoCommit:
    """O gate precisa saber de QUAL scan ele está decidindo.

    O bug: ``_extract_commit`` só olhava dentro dos findings, e o payload que
    chega do Tier 2 vem com ``findings: []`` no caso mais comum — o log saía
    ``tier3_skipped commit_sha=``.
    """

    def _eventos(self, mock_logger) -> dict[str, dict]:
        return {
            call.args[0]: call.kwargs
            for call in mock_logger.info.call_args_list + mock_logger.warning.call_args_list
        }

    def test_commit_do_payload_e_logado_com_findings_vazio(self):
        analysis = _analysis([], commit_sha=SHA)
        with patch.object(analysis_worker, "logger") as mock_logger:
            ar = analysis_worker.tier3_gate.delay(analysis)
        assert ar.state == "IGNORED"
        assert self._eventos(mock_logger)["tier3_skipped"]["commit_sha"] == SHA

    def test_commit_do_payload_e_logado_na_escalacao(self):
        analysis = _analysis([_f(severity="critical")], commit_sha=SHA)
        with patch.object(analysis_worker, "logger") as mock_logger:
            analysis_worker.tier3_gate.delay(analysis).get()
        assert self._eventos(mock_logger)["tier3_escalated"]["commit_sha"] == SHA

    def test_kwarg_explicito_ganha_do_payload(self):
        """Se o canvas um dia injetar o commit, ele é a fonte da verdade."""
        analysis = _analysis([], commit_sha="b" * 40)
        with patch.object(analysis_worker, "logger") as mock_logger:
            analysis_worker.tier3_gate.delay(analysis, commit_sha=SHA)
        assert self._eventos(mock_logger)["tier3_skipped"]["commit_sha"] == SHA

    def test_payload_legado_ainda_le_o_commit_dos_findings(self):
        """Rede de segurança: payload sem a chave, mas com findings."""
        analysis = _analysis([_f(severity="low", commit_sha=SHA)])
        with patch.object(analysis_worker, "logger") as mock_logger:
            analysis_worker.tier3_gate.delay(analysis)
        assert self._eventos(mock_logger)["tier3_skipped"]["commit_sha"] == SHA

    def test_sem_commit_em_lugar_nenhum_loga_aviso(self):
        analysis = _analysis([])
        with patch.object(analysis_worker, "logger") as mock_logger:
            analysis_worker.tier3_gate.delay(analysis)
        assert "tier3_gate_sem_commit" in self._eventos(mock_logger)


# -----------------------------------------------------------------------------
# A decisão do gate vira estado persistido
# -----------------------------------------------------------------------------


@pytest.fixture
def sqlite_factory():
    eng = create_engine(
        "sqlite://",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
        future=True,
    )
    Base.metadata.create_all(eng)
    factory = sessionmaker(bind=eng, expire_on_commit=False, autoflush=False)
    try:
        yield factory
    finally:
        eng.dispose()


@pytest.fixture
def persistence_on(sqlite_factory):
    """Religa a persistência do ScanJob (o autouse do conftest desliga)."""
    original = settings.SCAN_PERSISTENCE_ENABLED
    settings.SCAN_PERSISTENCE_ENABLED = True
    with patch.object(scan_job_writer, "SessionLocal", sqlite_factory):
        scan_job_writer.create_scan_job(
            commit_sha=SHA,
            repo_url="https://github.com/acme/repo",
            installation_id=1,
        )
        yield sqlite_factory
    settings.SCAN_PERSISTENCE_ENABLED = original


def _job(factory):
    with factory() as s:
        return SQLAlchemyScanJobRepository(s).get_by_commit(SHA)


class TestPersistenciaDaDecisao:
    def test_skip_grava_skipped(self, persistence_on):
        """NULL no dashboard é um traço apagado — a decisão precisa aparecer."""
        ar = analysis_worker.tier3_gate.delay(_analysis([], commit_sha=SHA))
        assert ar.state == "IGNORED"
        assert _job(persistence_on).tier3_status == TierStatus.SKIPPED

    def test_escalacao_continua_gravando_running(self, persistence_on):
        analysis = _analysis([_f(severity="critical")], commit_sha=SHA)
        analysis_worker.tier3_gate.delay(analysis).get()
        job = _job(persistence_on)
        assert job.tier3_status == TierStatus.RUNNING
        assert job.tier3_started_at is not None

    def test_skip_nao_sobrescreve_tier3_concluido(self, persistence_on):
        """Gate fora de ordem (retry do canvas) não pode apagar um T3 real."""
        scan_job_writer.mark_tier(SHA, 3, "done")
        analysis_worker.tier3_gate.delay(_analysis([], commit_sha=SHA))
        assert _job(persistence_on).tier3_status == TierStatus.DONE

    def test_sem_commit_nao_grava_nada(self, persistence_on):
        """Sem identidade não há o que gravar — e o gate não pode quebrar."""
        ar = analysis_worker.tier3_gate.delay(_analysis([]))
        assert ar.state == "IGNORED"
        assert _job(persistence_on).tier3_status is None


class TestCeleryRegistration:
    def test_task_in_registry(self):
        from app.core.celery_app import celery_app

        assert (
            "app.presentation.workers.analysis_worker.tier3_gate"
            in celery_app.tasks
        )

    def test_task_routed_to_analysis_queue(self):
        from app.core.celery_app import celery_app

        routes = celery_app.conf.task_routes
        assert routes["app.presentation.workers.analysis_worker.*"]["queue"] == "analysis"


class TestEscalaPorRiscoAgregado:
    """O gate passou a olhar o risco agregado, não só a severidade individual.

    Antes só o critério 1 existia, e ele ignora volume e correlação — que é o
    que o Tier 2 acabou de calcular. 57 possíveis secrets `medium` somando risco
    `high` (74/100) não escalavam: nenhum item sozinho cruzava a barra.
    """

    def _analysis(self, *, severidade: str, nivel: str, n: int = 3) -> dict:
        return {
            "commit_sha": "a" * 40,
            "findings": [
                {"severity": severidade, "title": f"f{i}"} for i in range(n)
            ],
            "risk_score": {"score": 74, "level": nivel},
        }

    def test_escala_por_risco_agregado_mesmo_com_findings_medium(self):
        with patch.object(analysis_worker.scan_job_writer, "mark_tier") as mark, patch.object(
            analysis_worker.scan_job_writer, "mark_tier_skipped"
        ) as skip:
            saida = analysis_worker.tier3_gate(
                self._analysis(severidade="medium", nivel="high")
            )

        assert saida is not None
        mark.assert_called_once()
        assert mark.call_args[0][1:] == (3, "running")
        skip.assert_not_called()

    def test_continua_escalando_por_severidade_individual(self):
        """O critério antigo não pode ter regredido."""
        with patch.object(analysis_worker.scan_job_writer, "mark_tier") as mark:
            saida = analysis_worker.tier3_gate(
                self._analysis(severidade="critical", nivel="low")
            )

        assert saida is not None
        mark.assert_called_once()

    def test_pula_quando_nenhum_dos_dois_criterios_vale(self):
        with patch.object(analysis_worker.scan_job_writer, "mark_tier_skipped") as skip:
            with pytest.raises(Ignore):
                analysis_worker.tier3_gate(
                    self._analysis(severidade="medium", nivel="medium")
                )
        skip.assert_called_once()

    def test_risk_score_adjusted_tem_precedencia(self):
        """Mesma ordem que `scan_job_writer` usa para gravar final_risk_level."""
        payload = self._analysis(severidade="low", nivel="low")
        payload["risk_score_adjusted"] = {"score": 91, "level": "critical"}

        with patch.object(analysis_worker.scan_job_writer, "mark_tier") as mark:
            assert analysis_worker.tier3_gate(payload) is not None
        mark.assert_called_once()

    @pytest.mark.parametrize("risco", [None, {}, "alto", {"level": None}])
    def test_risk_score_malformado_nao_quebra_o_gate(self, risco):
        payload = self._analysis(severidade="low", nivel="low")
        payload["risk_score"] = risco

        with patch.object(analysis_worker.scan_job_writer, "mark_tier_skipped"):
            with pytest.raises(Ignore):
                analysis_worker.tier3_gate(payload)
