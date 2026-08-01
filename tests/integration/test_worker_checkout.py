"""Integração dos scan workers com o checkout efêmero do repositório.

Cobre o que o teste unitário do ``repo_checkout`` não vê: se as tasks pedem o
checkout com os dados certos, se o escopo do Semgrep vira o diff do PR (ou a
árvore inteira), e o que acontece com o ``ScanJob`` quando o checkout falha.

O ``conftest`` já troca o checkout real por um diretório temporário vazio; aqui
sobrescrevemos esse patch quando o teste precisa inspecionar os argumentos ou
simular falha.
"""

from __future__ import annotations

from contextlib import contextmanager
from unittest.mock import MagicMock, patch

import pytest

from app.core.exceptions import RepoCheckoutError
from app.presentation.workers import (
    checkout_guard,
    tier1_scan_worker,
    tier2_scan_worker,
)

COMMIT = "a" * 40
BASE = "b" * 40


@pytest.fixture
def checkout_espiao():
    """Registra os kwargs do checkout e entrega um caminho fixo."""
    chamadas: list[dict] = []

    @contextmanager
    def _fake(**kwargs):
        chamadas.append(kwargs)
        yield "/tmp/checkout-falso"

    with patch.object(checkout_guard, "checkout_repo", _fake):
        yield chamadas


@pytest.fixture
def checkout_quebrado():
    """Simula falha de checkout (token expirado, repo sumiu, rede)."""

    @contextmanager
    def _boom(**_kwargs):
        raise RepoCheckoutError("checkout (fetch) falhou (rc=128): fatal: not found")
        yield  # pragma: no cover — inalcançável, mantém a função geradora

    with patch.object(checkout_guard, "checkout_repo", _boom):
        yield


class TestTier1UsaOCheckout:
    def test_trufflehog_pede_checkout_do_commit(self, checkout_espiao):
        with patch.object(tier1_scan_worker, "TruffleHogScanner") as Scanner:
            Scanner.return_value.run_safe.return_value = []
            tier1_scan_worker.run_trufflehog.delay(
                repo_full_name="acme/repo",
                installation_id=42,
                base_sha=BASE,
                head_sha=COMMIT,
                commit_sha=COMMIT,
                repo_url="https://github.com/acme/repo",
            ).get()

        assert checkout_espiao == [
            {
                "repo_full_name": "acme/repo",
                "commit_sha": COMMIT,
                "installation_id": 42,
                # O base entra no checkout por causa do ``--since-commit``.
                "base_sha": BASE,
            }
        ]
        # O scanner roda contra a árvore recém-materializada, não contra stub.
        assert (
            Scanner.return_value.run_safe.call_args.kwargs["repo_path"]
            == "/tmp/checkout-falso"
        )

    def test_semgrep_usa_o_diff_do_pr_como_escopo(self, checkout_espiao):
        with patch.object(tier1_scan_worker, "SemgrepScanner") as Scanner, patch.object(
            tier1_scan_worker, "listar_arquivos_alterados", return_value=["app/db.py"]
        ) as diff:
            Scanner.return_value.run_safe.return_value = []
            tier1_scan_worker.run_semgrep_changed.delay(
                repo_full_name="acme/repo",
                installation_id=42,
                changed_files=[],
                base_sha=BASE,
                commit_sha=COMMIT,
                repo_url="https://github.com/acme/repo",
            ).get()

        diff.assert_called_once_with(
            "/tmp/checkout-falso", base_sha=BASE, head_sha=COMMIT
        )
        assert Scanner.return_value.run_safe.call_args.kwargs["changed_files"] == [
            "app/db.py"
        ]

    def test_scan_manual_sem_base_varre_a_arvore_inteira(self, checkout_espiao):
        """Scan de branch: ``base_sha == commit_sha`` → lista vazia = árvore toda."""
        with patch.object(tier1_scan_worker, "SemgrepScanner") as Scanner:
            Scanner.return_value.run_safe.return_value = []
            tier1_scan_worker.run_semgrep_changed.delay(
                repo_full_name="acme/repo",
                installation_id=42,
                changed_files=[],
                base_sha=COMMIT,
                commit_sha=COMMIT,
                repo_url="https://github.com/acme/repo",
            ).get()

        assert Scanner.return_value.run_safe.call_args.kwargs["changed_files"] == []

    def test_changed_files_explicito_tem_precedencia(self, checkout_espiao):
        with patch.object(tier1_scan_worker, "SemgrepScanner") as Scanner, patch.object(
            tier1_scan_worker, "listar_arquivos_alterados"
        ) as diff:
            Scanner.return_value.run_safe.return_value = []
            tier1_scan_worker.run_semgrep_changed.delay(
                repo_full_name="acme/repo",
                installation_id=42,
                changed_files=["main.py"],
                base_sha=BASE,
                commit_sha=COMMIT,
                repo_url="https://github.com/acme/repo",
            ).get()

        diff.assert_not_called()
        assert Scanner.return_value.run_safe.call_args.kwargs["changed_files"] == [
            "main.py"
        ]


class TestTier2UsaOCheckout:
    def test_trivy_roda_contra_o_checkout(self, checkout_espiao):
        with patch.object(tier2_scan_worker, "TrivyScanner") as Trivy, patch.object(
            tier2_scan_worker, "_SemgrepExpandedAdapter"
        ) as Semgrep, patch.object(tier2_scan_worker, "ProwlerScanner"):
            Trivy.return_value.run_safe.return_value = []
            Semgrep.return_value.run_safe.return_value = []
            tier2_scan_worker.run_tier2_scan.delay(
                repo_full_name="acme/repo",
                installation_id=42,
                changed_files=[],
                base_sha=BASE,
                commit_sha=COMMIT,
                repo_url="https://github.com/acme/repo",
            ).get()

        assert checkout_espiao[0]["installation_id"] == 42
        assert (
            Trivy.return_value.run_safe.call_args.kwargs["target"]
            == "/tmp/checkout-falso"
        )

    def test_diff_do_pr_reativa_o_prowler(self, checkout_espiao):
        """Sem diff o Prowler nunca rodava — o canvas não carrega changed_files."""
        with patch.object(tier2_scan_worker, "TrivyScanner") as Trivy, patch.object(
            tier2_scan_worker, "_SemgrepExpandedAdapter"
        ) as Semgrep, patch.object(
            tier2_scan_worker, "ProwlerScanner"
        ) as Prowler, patch.object(
            tier2_scan_worker, "listar_arquivos_alterados", return_value=["infra/main.tf"]
        ):
            Trivy.return_value.run_safe.return_value = []
            Semgrep.return_value.run_safe.return_value = []
            Prowler.return_value.run_safe.return_value = []
            tier2_scan_worker.run_tier2_scan.delay(
                repo_full_name="acme/repo",
                installation_id=42,
                changed_files=[],
                base_sha=BASE,
                commit_sha=COMMIT,
                repo_url="https://github.com/acme/repo",
            ).get()

        Prowler.return_value.run_safe.assert_called_once()


class TestFalhaDeCheckout:
    def test_task_falha_em_vez_de_devolver_zero_findings(self, checkout_quebrado):
        with patch.object(tier1_scan_worker, "TruffleHogScanner") as Scanner:
            with pytest.raises(RepoCheckoutError):
                tier1_scan_worker.run_trufflehog.delay(
                    repo_full_name="acme/repo",
                    installation_id=42,
                    base_sha=BASE,
                    head_sha=COMMIT,
                    commit_sha=COMMIT,
                    repo_url="https://github.com/acme/repo",
                ).get()

        # Sem árvore não há scan: fingir sucesso seria concluir "nada encontrado".
        Scanner.return_value.run_safe.assert_not_called()

    def test_tiers_pendentes_sao_encerrados(self, checkout_quebrado):
        """Senão o ScanJob fica ``running`` até a varredura de jobs travados."""
        writer = MagicMock()
        with patch.object(checkout_guard, "scan_job_writer", writer):
            with pytest.raises(RepoCheckoutError):
                tier2_scan_worker.run_tier2_scan.delay(
                    repo_full_name="acme/repo",
                    installation_id=42,
                    changed_files=[],
                    base_sha=BASE,
                    commit_sha=COMMIT,
                    repo_url="https://github.com/acme/repo",
                ).get()

        writer.fail_pending_tiers.assert_called_once()
        assert writer.fail_pending_tiers.call_args.args[0] == COMMIT
        assert "checkout_tier2" in writer.fail_pending_tiers.call_args.kwargs["motivo"]

    def test_motivo_registrado_no_log(self, checkout_quebrado):
        from structlog.testing import capture_logs

        with capture_logs() as logs:
            with pytest.raises(RepoCheckoutError):
                tier1_scan_worker.run_semgrep_changed.delay(
                    repo_full_name="acme/repo",
                    installation_id=42,
                    changed_files=[],
                    base_sha=BASE,
                    commit_sha=COMMIT,
                    repo_url="https://github.com/acme/repo",
                ).get()

        eventos = [linha["event"] for linha in logs]
        assert "scan_checkout_falhou" in eventos
