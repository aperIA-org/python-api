"""Testes dos workers Tier 3 — scan + deep_analysis + report.

Dependências externas (ZAP, OpenCTI, Caldera, Claude, GitHub) são
sempre mockadas via ``patch`` no namespace do worker — Celery não
serializa MagicMock como kwarg.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from app.domain.finding.entities import Finding
from app.domain.finding.value_objects import Severity
from app.presentation.workers import (
    analysis_worker,
    reporting_worker,
    tier3_scan_worker,
)


def _make_zap_finding(**overrides) -> Finding:
    base = {
        "source": "zap",
        "severity": Severity.HIGH,
        "title": "SQL Injection",
        "description": "x",
        "commit_sha": "a" * 40,
        "repo_url": "https://github.com/x/y",
        "asset": "http://localhost:8080/app/login",
        "tier": 3,
    }
    base.update(overrides)
    return Finding(**base)


# =============================================================================
# tier3_scan_worker.run_tier3_scan
# =============================================================================


@pytest.fixture
def patched_t3_deps():
    """Mocka ZAPScanner, OpenCTIClient, CalderaClient no namespace do worker."""
    with patch.object(tier3_scan_worker, "ZAPScanner") as Z, patch.object(
        tier3_scan_worker, "OpenCTIClient"
    ) as O, patch.object(tier3_scan_worker, "CalderaClient") as C:
        Z.return_value.run_safe.return_value = []
        O.return_value.enrich_cve.return_value = None
        C.return_value.run_safe.return_value = {
            "status": "ok",
            "success_rate": 0.0,
            "caldera_validated": False,
            "techniques_executed": 0,
            "techniques_successful": 0,
            "ttps_used": [],
        }
        yield {"zap": Z, "opencti": O, "caldera": C}


class TestTier3ScanWorker:
    def test_zap_skipped_when_no_target_url(self, patched_t3_deps):
        result = tier3_scan_worker.run_tier3_scan.delay(
            target_url=None,
            t2_findings=[],
            commit_sha="a" * 40,
            repo_url="https://github.com/x/y",
        ).get()
        patched_t3_deps["zap"].return_value.run_safe.assert_not_called()
        assert result["findings"] == []

    def test_zap_runs_when_target_url_present(self, patched_t3_deps):
        patched_t3_deps["zap"].return_value.run_safe.return_value = [
            _make_zap_finding()
        ]
        result = tier3_scan_worker.run_tier3_scan.delay(
            target_url="http://localhost:8080/app",
            t2_findings=[],
            commit_sha="a" * 40,
            repo_url="https://github.com/x/y",
        ).get()
        patched_t3_deps["zap"].return_value.run_safe.assert_called_once()
        assert len(result["findings"]) == 1
        assert result["findings"][0]["source"] == "zap"
        assert result["findings"][0]["tier"] == 3

    def test_opencti_enriches_each_distinct_cve(self, patched_t3_deps):
        patched_t3_deps["opencti"].return_value.enrich_cve.side_effect = [
            {
                "cve_id": "CVE-2021-44228",
                "mitre_techniques": ["T1190"],
                "active_threat": True,
            },
            {
                "cve_id": "CVE-2022-22965",
                "mitre_techniques": ["T1059"],
                "active_threat": True,
            },
        ]
        result = tier3_scan_worker.run_tier3_scan.delay(
            target_url=None,
            t2_findings=[
                {"cve_id": "CVE-2021-44228", "severity": "critical"},
                {"cve_id": "CVE-2021-44228", "severity": "critical"},  # repetido
                {"cve_id": "CVE-2022-22965", "severity": "high"},
                {"cve_id": None, "severity": "low"},  # sem CVE
            ],
            commit_sha="a" * 40,
            repo_url="https://github.com/x/y",
        ).get()
        # Apenas 2 CVEs distintos
        assert patched_t3_deps["opencti"].return_value.enrich_cve.call_count == 2
        # CTI merged tem ambas as TTPs
        assert result["cti_data"]["active_threat"] is True
        assert "T1190" in result["cti_data"]["mitre_techniques"]
        assert "T1059" in result["cti_data"]["mitre_techniques"]

    def test_cti_empty_when_no_cves(self, patched_t3_deps):
        result = tier3_scan_worker.run_tier3_scan.delay(
            target_url=None,
            t2_findings=[{"severity": "high", "cve_id": None}],
            commit_sha="a" * 40,
            repo_url="x",
        ).get()
        assert result["cti_data"] == {}

    def test_caldera_invoked_with_merged_ttps(self, patched_t3_deps):
        patched_t3_deps["opencti"].return_value.enrich_cve.return_value = {
            "mitre_techniques": ["T1190"],
            "active_threat": True,
        }
        tier3_scan_worker.run_tier3_scan.delay(
            target_url=None,
            t2_findings=[{"cve_id": "CVE-2021-44228"}],
            commit_sha="a" * 40,
            repo_url="x",
        ).get()
        kwargs = patched_t3_deps["caldera"].return_value.run_safe.call_args.kwargs
        assert kwargs["mitre_techniques"] == ["T1190"]

    def test_returns_aggregate_dict(self, patched_t3_deps):
        result = tier3_scan_worker.run_tier3_scan.delay(
            target_url=None,
            t2_findings=[],
            commit_sha="a" * 40,
            repo_url="x",
        ).get()
        assert set(result.keys()) == {"findings", "cti_data", "caldera_results"}


# =============================================================================
# analysis_worker.tier3_deep_analysis
# =============================================================================


@pytest.fixture
def patched_deep_claude():
    with patch.object(analysis_worker, "ClaudeClient") as MockClass:
        yield MockClass.return_value


class TestTier3DeepAnalysis:
    def test_calls_claude_with_attack_path_prompt(self, patched_deep_claude):
        patched_deep_claude.call_json.return_value = {
            "attack_path": [
                {
                    "step": 1,
                    "phase": "initial_access",
                    "technique": "T1190",
                    "description": "RCE em endpoint público",
                    "finding_ids": ["x"],
                    "caldera_validated": True,
                }
            ],
            "kill_chain_complete": False,
            "prioritized_actions": [],
            "risk_score_adjusted": {"score": 80, "level": "high"},
            "cti_status": "available",
            "caldera_status": "available",
        }
        result = analysis_worker.tier3_deep_analysis.delay(
            {
                "findings": [{"severity": "critical", "source": "zap"}],
                "cti_data": {"active_threat": True, "mitre_techniques": ["T1190"]},
                "caldera_results": {
                    "status": "ok",
                    "success_rate": 0.8,
                    "caldera_validated": True,
                },
            },
            commit_sha="a" * 40,
            tier2_analysis={
                "findings": [{"severity": "high", "source": "semgrep"}]
            },
        ).get()
        assert result["degraded"] is False
        assert result["risk_score_adjusted"]["score"] == 80
        kwargs = patched_deep_claude.call_json.call_args.kwargs
        # Findings agregados de T2 + T3
        assert "Findings (2)" in kwargs["user"]
        # SYSTEM é o de attack_path
        assert "MITRE ATT&CK" in kwargs["system"]

    def test_anexa_validacao_por_evidencia_e_alimenta_o_prompt(
        self, patched_deep_claude
    ):
        """A validacao por evidencia e deterministica: computada dos findings,
        anexada ao resultado e injetada no prompt — para o modelo nao declarar
        "nao validado" sobre o que ZAP/TruffleHog ja confirmaram."""
        patched_deep_claude.call_json.return_value = {
            "attack_path": [],
            "kill_chain_complete": False,
            "prioritized_actions": [],
            "risk_score_adjusted": {"score": 70, "level": "high"},
            "cti_status": "unavailable",
            "caldera_status": "unavailable",
        }
        result = analysis_worker.tier3_deep_analysis.delay(
            {
                "findings": [
                    {
                        "source": "zap",
                        "title": "XSS refletido",
                        "raw_output": {"attack": "<script>", "confidence": "Medium"},
                    }
                ],
                "cti_data": {},
                "caldera_results": {},
            },
            commit_sha="a" * 40,
            tier2_analysis={
                "findings": [
                    {"source": "trufflehog", "secret_verified": True, "title": "AWS"},
                    {"source": "semgrep", "title": "SQLi", "raw_output": {}},
                ]
            },
        ).get()

        val = result["validacao_evidencia"]
        assert val["total"] == 3
        assert val["confirmados"] == 2  # secret vivo + zap ativo; semgrep nao
        # o prompt recebeu o bloco deterministico
        prompt = patched_deep_claude.call_json.call_args.kwargs["user"]
        assert "Validacao por evidencia" in prompt
        assert "CONFIRMADO" in prompt

    def test_circuit_open_yields_degraded(self, patched_deep_claude):
        from app.infrastructure.ai.claude_client import CircuitOpenError

        patched_deep_claude.call_json.side_effect = CircuitOpenError("open")
        result = analysis_worker.tier3_deep_analysis.delay(
            {"findings": [], "cti_data": {}, "caldera_results": {}},
            commit_sha="a" * 40,
        ).get()
        assert result["degraded"] is True
        assert result["reason"] == "CircuitOpenError"

    def test_caldera_failed_status_marks_unavailable(self, patched_deep_claude):
        patched_deep_claude.call_json.return_value = {
            "attack_path": [],
            "risk_score_adjusted": {"score": 10, "level": "low"},
            "prioritized_actions": [],
        }
        result = analysis_worker.tier3_deep_analysis.delay(
            {
                "findings": [{"severity": "high"}],
                "cti_data": {},
                "caldera_results": {"status": "failed", "reason": "timeout"},
            },
            commit_sha="a" * 40,
        ).get()
        assert result["caldera_status"] == "unavailable"
        assert result["cti_status"] == "unavailable"


# =============================================================================
# reporting_worker.post_tier3_deep_report
# =============================================================================


@pytest.fixture
def patched_reporting_claude_t3():
    with patch.object(reporting_worker, "ClaudeClient") as MockClass:
        yield MockClass.return_value


@pytest.fixture
def patched_reporting_github_t3():
    with patch.object(reporting_worker, "GitHubClient") as MockClass:
        yield MockClass.return_value


class TestPostTier3DeepReport:
    def test_posts_claude_generated_t3_report(
        self, patched_reporting_claude_t3, patched_reporting_github_t3
    ):
        patched_reporting_claude_t3.call.return_value = MagicMock(
            text="## T3 markdown"
        )
        patched_reporting_github_t3.post_pr_comment.return_value = 555

        result = reporting_worker.post_tier3_deep_report.delay(
            {
                "degraded": False,
                "attack_path": [],
                "risk_score_adjusted": {"score": 70, "level": "high"},
                "prioritized_actions": [],
                "cti_status": "available",
                "caldera_status": "available",
            },
            repo_full_name="acme/repo",
            pr_number=7,
            commit_sha="a" * 40,
            installation_id=42,
        ).get()
        assert result["_post_meta"]["posted"] is True
        assert result["_post_meta"]["comment_id"] == 555
        # Análise preservada para inspeção posterior
        assert result["risk_score_adjusted"]["score"] == 70
        body = patched_reporting_github_t3.post_pr_comment.call_args.kwargs[
            "body"
        ]
        assert "T3 markdown" in body

    def test_anexa_secao_deterministica_de_validacao_ao_body(
        self, patched_reporting_claude_t3, patched_reporting_github_t3
    ):
        """A secao de validacao por evidencia e anexada em CODIGO, entao aparece
        mesmo que o markdown do modelo nao a mencione."""
        patched_reporting_claude_t3.call.return_value = MagicMock(text="## T3")
        patched_reporting_github_t3.post_pr_comment.return_value = 1
        reporting_worker.post_tier3_deep_report.delay(
            {
                "degraded": False,
                "attack_path": [],
                "risk_score_adjusted": {"score": 70, "level": "high"},
                "prioritized_actions": [],
                "cti_status": "unavailable",
                "caldera_status": "unavailable",
                "validacao_evidencia": {
                    "total": 3,
                    "confirmados": 2,
                    "grupos": [
                        {
                            "metodo": "secret_vivo",
                            "rotulo": "credencial verificada como válida",
                            "confirmado": True,
                            "total": 1,
                            "exemplos": ["AWS key"],
                        },
                        {
                            "metodo": "nao_validado",
                            "rotulo": "sinalizada por análise",
                            "confirmado": False,
                            "total": 2,
                            "exemplos": ["SQLi"],
                        },
                    ],
                },
            },
            repo_full_name="acme/repo",
            pr_number=7,
            commit_sha="a" * 40,
            installation_id=42,
        ).get()
        body = patched_reporting_github_t3.post_pr_comment.call_args.kwargs["body"]
        assert "## T3" in body  # markdown do modelo preservado
        assert "2 de 3 finding(s) confirmado(s)" in body
        assert "credencial verificada como válida" in body

    def test_degraded_uses_fallback_markdown(
        self, patched_reporting_claude_t3, patched_reporting_github_t3
    ):
        patched_reporting_github_t3.post_pr_comment.return_value = 1
        result = reporting_worker.post_tier3_deep_report.delay(
            {
                "degraded": True,
                "reason": "CircuitOpenError",
                "findings": [
                    {
                        "severity": "high",
                        "source": "zap",
                        "title": "SQLi",
                        "file_path": "N/A",
                        "line_number": "?",
                    }
                ],
                "cti_data": {"mitre_techniques": ["T1190"]},
                "caldera_results": {
                    "status": "ok",
                    "success_rate": 0.5,
                    "caldera_validated": True,
                },
            },
            repo_full_name="acme/repo",
            pr_number=7,
            commit_sha="a" * 40,
            installation_id=42,
        ).get()
        assert result["_post_meta"]["posted"] is True
        patched_reporting_claude_t3.call.assert_not_called()
        body = patched_reporting_github_t3.post_pr_comment.call_args.kwargs[
            "body"
        ]
        assert "modo degradado" in body
        assert "SQLi" in body
        assert "T1190" in body
        assert "50%" in body

    def test_claude_failure_falls_back(
        self, patched_reporting_claude_t3, patched_reporting_github_t3
    ):
        from app.infrastructure.ai.claude_client import GuardBlockedError

        patched_reporting_claude_t3.call.side_effect = GuardBlockedError("inj")
        patched_reporting_github_t3.post_pr_comment.return_value = 1

        result = reporting_worker.post_tier3_deep_report.delay(
            {
                "degraded": False,
                "attack_path": [],
                "risk_score_adjusted": {"score": 50, "level": "medium"},
                "prioritized_actions": [],
                "findings": [],
            },
            repo_full_name="acme/repo",
            pr_number=7,
            commit_sha="a" * 40,
            installation_id=42,
        ).get()
        assert result["_post_meta"]["posted"] is True
        body = patched_reporting_github_t3.post_pr_comment.call_args.kwargs[
            "body"
        ]
        assert "modo degradado" in body


# =============================================================================
# Celery registration
# =============================================================================


class TestRegistration:
    def test_all_t3_tasks_registered(self):
        from app.core.celery_app import celery_app

        expected = {
            "app.presentation.workers.tier3_scan_worker.run_tier3_scan",
            "app.presentation.workers.analysis_worker.tier3_deep_analysis",
            "app.presentation.workers.reporting_worker.post_tier3_deep_report",
        }
        assert expected.issubset(set(celery_app.tasks.keys()))

    def test_tier3_route(self):
        from app.core.celery_app import celery_app

        assert (
            celery_app.conf.task_routes[
                "app.presentation.workers.tier3_scan_worker.*"
            ]["queue"]
            == "tier3"
        )
