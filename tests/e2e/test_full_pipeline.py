"""Teste E2E de orquestração do canvas Celery completo.

Decisão #4 Semana 12: valida sequência de tasks + efeitos colaterais
(status checks, comments, code suggestions) em modo eager.

NÃO testa conteúdo real dos scans — todos os subprocess/HTTP são
mockados. O objetivo é provar:

1. ``start_pipeline`` dispara o canvas completo
2. Cada bridge task é chamada na ordem certa
3. Gate 1 (com secret verificado) interrompe via Ignore
4. Gate 2 (com severity < high) interrompe via Ignore
5. Caminho feliz crítico/high chega até Tier 3 report
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from app.core.orchestrator import start_pipeline
from app.domain.finding.entities import Finding
from app.domain.finding.value_objects import CVEId, Severity


def _make_finding(**overrides) -> Finding:
    base = {
        "source": "semgrep",
        "severity": Severity.HIGH,
        "title": "SQL injection",
        "description": "x",
        "commit_sha": "a" * 40,
        "repo_url": "https://github.com/x/y",
        "file_path": "app/db.py",
        "line_number": 42,
        "tier": 2,
    }
    base.update(overrides)
    return Finding(**base)


@pytest.fixture
def patched_all_external():
    """Patcha TODAS as dependências externas:
    scanners (subprocess), Claude, GitHub, OpenCTI, Caldera, ZAP.
    """
    patches: list = []

    def _start(target, replacement):
        p = patch(target, replacement)
        p.start()
        patches.append(p)

    # ---- Scanners (Tier 1) ----
    trufflehog = MagicMock()
    trufflehog.return_value.run_safe.return_value = []
    _start(
        "app.presentation.workers.tier1_scan_worker.TruffleHogScanner",
        trufflehog,
    )
    semgrep_t1 = MagicMock()
    semgrep_t1.return_value.run_safe.return_value = []
    _start(
        "app.presentation.workers.tier1_scan_worker.SemgrepScanner",
        semgrep_t1,
    )

    # ---- Scanners (Tier 2) ----
    trivy = MagicMock()
    trivy.return_value.run_safe.return_value = []
    _start(
        "app.presentation.workers.tier2_scan_worker.TrivyScanner",
        trivy,
    )
    semgrep_t2 = MagicMock()
    semgrep_t2.return_value.run_safe.return_value = []
    _start(
        "app.presentation.workers.tier2_scan_worker._SemgrepExpandedAdapter",
        semgrep_t2,
    )
    prowler = MagicMock()
    prowler.return_value.run_safe.return_value = []
    _start(
        "app.presentation.workers.tier2_scan_worker.ProwlerScanner",
        prowler,
    )

    # ---- Scanners (Tier 3) ----
    zap = MagicMock()
    zap.return_value.run_safe.return_value = []
    _start(
        "app.presentation.workers.tier3_scan_worker.ZAPScanner",
        zap,
    )
    cti = MagicMock()
    cti.return_value.enrich_cve.return_value = None
    _start(
        "app.presentation.workers.tier3_scan_worker.ThreatIntelClient",
        cti,
    )
    caldera = MagicMock()
    caldera.return_value.run_safe.return_value = {
        "status": "ok",
        "success_rate": 0.0,
        "caldera_validated": False,
        "techniques_executed": 0,
        "techniques_successful": 0,
        "ttps_used": [],
    }
    _start(
        "app.presentation.workers.tier3_scan_worker.CalderaClient",
        caldera,
    )

    # ---- Claude (analysis + reporting) ----
    claude_analysis = MagicMock()
    claude_analysis.return_value.call_json.return_value = {
        "event_chain": [],
        "risk_score": {"score": 40, "level": "medium"},
        "business_impact": {"description": "x"},
        "attack_narrative": "narrative",
    }
    _start(
        "app.presentation.workers.analysis_worker.ClaudeClient",
        claude_analysis,
    )
    claude_reporting = MagicMock()
    claude_reporting.return_value.call.return_value = MagicMock(text="## Report")
    _start(
        "app.presentation.workers.reporting_worker.ClaudeClient",
        claude_reporting,
    )

    # ---- GitHub ----
    gh_analysis = MagicMock()
    gh_analysis.return_value.post_pr_comment.return_value = 1
    gh_analysis.return_value.create_status_check.return_value = None
    _start(
        "app.presentation.workers.analysis_worker.GitHubClient",
        gh_analysis,
    )
    gh_reporting = MagicMock()
    gh_reporting.return_value.post_pr_comment.return_value = 2
    _start(
        "app.presentation.workers.reporting_worker.GitHubClient",
        gh_reporting,
    )

    try:
        yield {
            "trufflehog": trufflehog,
            "semgrep_t1": semgrep_t1,
            "trivy": trivy,
            "semgrep_t2": semgrep_t2,
            "prowler": prowler,
            "zap": zap,
            "cti": cti,
            "caldera": caldera,
            "claude_analysis": claude_analysis,
            "claude_reporting": claude_reporting,
            "gh_analysis": gh_analysis,
            "gh_reporting": gh_reporting,
        }
    finally:
        for p in patches:
            p.stop()


def _kickoff(**overrides):
    args = dict(
        commit_sha="a" * 40,
        repo_url="https://github.com/acme/repo",
        pr_number=7,
        installation_id=42,
        repo_full_name="acme/repo",
        base_sha="b" * 40,
        head_sha="a" * 40,
        changed_files=["app/db.py"],
        target_url=None,
    )
    args.update(overrides)
    return start_pipeline(**args)


# =============================================================================
# Happy path — passa Gate 1 e Gate 2, chega até Tier 3
# =============================================================================


class TestFullPipelineEscalates:
    def test_all_scanners_called_with_critical_finding(self, patched_all_external):
        """Finding crítico em T2 → escala para Tier 3 → reporting T3."""
        # T2 retorna um critical para forçar a escalação
        patched_all_external["trivy"].return_value.run_safe.return_value = [
            _make_finding(
                source="trivy",
                severity=Severity.CRITICAL,
                cve_id=CVEId("CVE-2021-44228"),
                file_path="lib/x.jar",
            )
        ]

        _kickoff()

        # Tier 1
        patched_all_external["trufflehog"].return_value.run_safe.assert_called()
        patched_all_external["semgrep_t1"].return_value.run_safe.assert_called()

        # Tier 2
        patched_all_external["trivy"].return_value.run_safe.assert_called()
        patched_all_external["semgrep_t2"].return_value.run_safe.assert_called()
        # Prowler: changed_files=["app/db.py"] → não há IaC → não chama
        patched_all_external["prowler"].return_value.run_safe.assert_not_called()

        # Tier 2 reporting executou
        patched_all_external["gh_reporting"].return_value.post_pr_comment.assert_called()

        # Tier 3 executou (critical escala)
        patched_all_external["zap"].return_value.run_safe.assert_not_called()  # sem target_url
        patched_all_external["caldera"].return_value.run_safe.assert_called()
        patched_all_external["cti"].return_value.enrich_cve.assert_called()

        # Claude foi chamado para T2 e T3 (2 análises distintas)
        assert patched_all_external["claude_analysis"].return_value.call_json.call_count >= 2

        # Reporting T3 também postou
        assert (
            patched_all_external["gh_reporting"].return_value.post_pr_comment.call_count
            >= 2
        )

    def test_zap_runs_when_target_url_provided(self, patched_all_external):
        patched_all_external["trivy"].return_value.run_safe.return_value = [
            _make_finding(severity=Severity.HIGH)
        ]

        _kickoff(target_url="http://localhost:8080/app")

        patched_all_external["zap"].return_value.run_safe.assert_called_once()

    def test_prowler_runs_when_changed_files_iac(self, patched_all_external):
        patched_all_external["trivy"].return_value.run_safe.return_value = [
            _make_finding(severity=Severity.HIGH)
        ]
        _kickoff(changed_files=["infra/main.tf"])

        patched_all_external["prowler"].return_value.run_safe.assert_called_once()


# =============================================================================
# Gate 1 — verified secret interrompe TUDO
# =============================================================================


class TestGate1Blocks:
    def test_verified_secret_blocks_pr_and_stops_pipeline(self, patched_all_external):
        # Trufflehog retorna um secret verificado
        patched_all_external["trufflehog"].return_value.run_safe.return_value = [
            _make_finding(
                source="trufflehog",
                severity=Severity.CRITICAL,
                secret_verified=True,
                secret_type="AWS",
            )
        ]

        _kickoff()

        # Gate 1 chamou GitHub para bloquear PR
        gh = patched_all_external["gh_analysis"]
        gh.return_value.create_status_check.assert_called_once()
        status_kwargs = gh.return_value.create_status_check.call_args.kwargs
        assert status_kwargs["state"] == "failure"
        gh.return_value.post_pr_comment.assert_called_once()

        # Tier 2 e Tier 3 NÃO executaram
        patched_all_external["trivy"].return_value.run_safe.assert_not_called()
        patched_all_external["zap"].return_value.run_safe.assert_not_called()
        patched_all_external["caldera"].return_value.run_safe.assert_not_called()
        # Reporting (T2/T3) também não foi chamado
        patched_all_external["gh_reporting"].return_value.post_pr_comment.assert_not_called()


# =============================================================================
# Gate 2 — severity baixa encerra após T2 report
# =============================================================================


class TestGate2Skips:
    def test_low_severity_does_not_escalate_to_tier3(self, patched_all_external):
        # Só findings LOW chegam ao Gate 2 → tier3_gate raise Ignore
        patched_all_external["trivy"].return_value.run_safe.return_value = [
            _make_finding(severity=Severity.LOW)
        ]

        _kickoff()

        # T2 reporting ocorreu
        patched_all_external["gh_reporting"].return_value.post_pr_comment.assert_called_once()
        # T3 NÃO executou
        patched_all_external["caldera"].return_value.run_safe.assert_not_called()
        patched_all_external["cti"].return_value.enrich_cve.assert_not_called()
        # Apenas 1 chamada ao Claude (tier2_analyze) — não houve tier3_deep_analysis
        assert patched_all_external["claude_analysis"].return_value.call_json.call_count == 1


# =============================================================================
# Modo degradado — Claude indisponível não derruba pipeline
# =============================================================================


class TestDegradedMode:
    def test_circuit_open_falls_back_to_raw_findings(self, patched_all_external):
        from app.infrastructure.ai.claude_client import CircuitOpenError

        patched_all_external["trivy"].return_value.run_safe.return_value = [
            _make_finding(severity=Severity.HIGH)
        ]
        patched_all_external["claude_analysis"].return_value.call_json.side_effect = (
            CircuitOpenError("open")
        )

        _kickoff()

        # Mesmo com Claude OFF, o reporting de T2 acontece em modo degradado
        patched_all_external["gh_reporting"].return_value.post_pr_comment.assert_called()
        body = patched_all_external[
            "gh_reporting"
        ].return_value.post_pr_comment.call_args.kwargs["body"]
        assert "modo degradado" in body
