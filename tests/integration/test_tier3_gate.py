"""Testes do tier3_gate (Gate 2) — Semana 9.

Decisão #2: HIGH e CRITICAL escalam; INFO, LOW e MEDIUM encerram.
Decisão #3: skip == ``raise Ignore()``, nunca retornar dict.

Modo eager Celery do conftest converte ``Ignore`` em
``EagerResult.state == "IGNORED"`` — usamos isso para validar a
interrupção do chain.
"""
from __future__ import annotations

import pytest

from app.presentation.workers import analysis_worker


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
        "cti_status": "unavailable",
        "caldera_status": "unavailable",
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
