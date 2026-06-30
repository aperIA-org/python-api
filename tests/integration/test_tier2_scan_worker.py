"""Testes de integração do tier2_scan_worker.

Cada scanner é mockado no namespace do worker (não no módulo original)
para isolar subprocess e garantir que `run_safe` é o caminho usado.
"""
from __future__ import annotations

from unittest.mock import MagicMock, patch

import pytest

from app.domain.finding.entities import Finding
from app.domain.finding.value_objects import CVEId, Severity
from app.presentation.workers import tier2_scan_worker


def _make_finding(**overrides) -> Finding:
    base = {
        "source": "semgrep",
        "severity": Severity.HIGH,
        "title": "Issue",
        "description": "x",
        "commit_sha": "a" * 40,
        "repo_url": "https://github.com/acme/repo",
        "file_path": "app/x.py",
        "line_number": 1,
        "tier": 2,
    }
    base.update(overrides)
    return Finding(**base)


@pytest.fixture
def patched_scanners():
    """Mocka as três classes de scanner no namespace do worker."""
    with patch.object(tier2_scan_worker, "TrivyScanner") as Trivy, patch.object(
        tier2_scan_worker, "_SemgrepExpandedAdapter"
    ) as SemgrepExp, patch.object(
        tier2_scan_worker, "ProwlerScanner"
    ) as Prowler:
        Trivy.return_value.run_safe.return_value = []
        SemgrepExp.return_value.run_safe.return_value = []
        Prowler.return_value.run_safe.return_value = []
        yield {"trivy": Trivy, "semgrep": SemgrepExp, "prowler": Prowler}


class TestScannerExecution:
    def test_trivy_always_runs(self, patched_scanners):
        tier2_scan_worker.run_tier2_scan.delay(
            repo_path="/tmp/repo",
            changed_files=[],
            commit_sha="a" * 40,
            repo_url="https://github.com/x/y",
        ).get()
        patched_scanners["trivy"].return_value.run_safe.assert_called_once()
        kwargs = patched_scanners["trivy"].return_value.run_safe.call_args.kwargs
        assert kwargs["target"] == "/tmp/repo"

    def test_semgrep_expanded_always_runs(self, patched_scanners):
        tier2_scan_worker.run_tier2_scan.delay(
            repo_path="/tmp/repo",
            changed_files=[],
            commit_sha="a" * 40,
            repo_url="https://github.com/x/y",
        ).get()
        patched_scanners["semgrep"].return_value.run_safe.assert_called_once()

    def test_prowler_runs_when_iac_present(self, patched_scanners):
        tier2_scan_worker.run_tier2_scan.delay(
            repo_path="/tmp/repo",
            changed_files=["app.py", "main.tf"],
            commit_sha="a" * 40,
            repo_url="https://github.com/x/y",
        ).get()
        patched_scanners["prowler"].return_value.run_safe.assert_called_once()

    def test_prowler_skipped_when_no_iac(self, patched_scanners):
        tier2_scan_worker.run_tier2_scan.delay(
            repo_path="/tmp/repo",
            changed_files=["app.py", "test_app.py"],
            commit_sha="a" * 40,
            repo_url="https://github.com/x/y",
        ).get()
        patched_scanners["prowler"].return_value.run_safe.assert_not_called()

    def test_prowler_skipped_with_empty_changed_files(self, patched_scanners):
        tier2_scan_worker.run_tier2_scan.delay(
            repo_path="/tmp/repo",
            changed_files=[],
            commit_sha="a" * 40,
            repo_url="https://github.com/x/y",
        ).get()
        patched_scanners["prowler"].return_value.run_safe.assert_not_called()

    def test_cloud_provider_passed_to_prowler(self, patched_scanners):
        tier2_scan_worker.run_tier2_scan.delay(
            repo_path="/tmp/repo",
            changed_files=["main.tf"],
            commit_sha="a" * 40,
            repo_url="https://github.com/x/y",
            cloud_provider="azure",
        ).get()
        kwargs = patched_scanners["prowler"].return_value.run_safe.call_args.kwargs
        assert kwargs["provider"] == "azure"


class TestAggregationAndDedup:
    def test_findings_from_all_scanners_aggregated(self, patched_scanners):
        patched_scanners["trivy"].return_value.run_safe.return_value = [
            _make_finding(source="trivy", title="trivy-1", file_path="lib/a.js", line_number=10),
        ]
        patched_scanners["semgrep"].return_value.run_safe.return_value = [
            _make_finding(source="semgrep", title="semgrep-1", file_path="app/b.py", line_number=20),
            _make_finding(source="semgrep", title="semgrep-2", file_path="app/c.py", line_number=30),
        ]
        patched_scanners["prowler"].return_value.run_safe.return_value = [
            _make_finding(source="prowler", title="prowler-1", file_path=None, line_number=None),
        ]
        result = tier2_scan_worker.run_tier2_scan.delay(
            repo_path="/tmp/repo",
            changed_files=["main.tf"],
            commit_sha="a" * 40,
            repo_url="https://github.com/x/y",
        ).get()
        assert len(result) == 4
        sources = {r["source"] for r in result}
        assert sources == {"trivy", "semgrep", "prowler"}

    def test_deduplicator_removes_identical_findings(self, patched_scanners):
        # Mesmo source/file/line/commit em ambos scanners — duplicata real.
        common = dict(
            source="semgrep",
            file_path="dup.py",
            line_number=10,
            title="duplicate-finding",
        )
        patched_scanners["semgrep"].return_value.run_safe.return_value = [
            _make_finding(**common),
            _make_finding(**common),
        ]
        patched_scanners["trivy"].return_value.run_safe.return_value = []
        result = tier2_scan_worker.run_tier2_scan.delay(
            repo_path="/tmp/repo",
            changed_files=[],
            commit_sha="a" * 40,
            repo_url="https://github.com/x/y",
        ).get()
        assert len(result) == 1

    def test_cross_scanner_same_cve_not_deduplicated(self, patched_scanners):
        """Cross-scanner: mesma CVE/path em trivy e semgrep mantém 2.

        Por design o dedup_key inclui ``source`` — findings de scanners
        diferentes ficam separados. Permite ao analyzer correlacionar
        depois (mesma CVE com evidência de 2 fontes é mais forte).
        """
        cve = CVEId("CVE-2021-44228")
        patched_scanners["trivy"].return_value.run_safe.return_value = [
            _make_finding(
                source="trivy",
                cve_id=cve,
                file_path="lib/log4j.jar",
                line_number=None,
                title="trivy:log4shell",
            ),
        ]
        patched_scanners["semgrep"].return_value.run_safe.return_value = [
            _make_finding(
                source="semgrep",
                cve_id=cve,
                file_path="lib/log4j.jar",
                line_number=None,
                title="semgrep:log4shell",
            ),
        ]
        result = tier2_scan_worker.run_tier2_scan.delay(
            repo_path="/tmp/repo",
            changed_files=[],
            commit_sha="a" * 40,
            repo_url="https://github.com/x/y",
        ).get()
        assert len(result) == 2
        sources = sorted(r["source"] for r in result)
        assert sources == ["semgrep", "trivy"]


class TestSerialization:
    def test_returns_json_safe_dicts(self, patched_scanners):
        patched_scanners["trivy"].return_value.run_safe.return_value = [
            _make_finding(
                source="trivy",
                cve_id=CVEId("CVE-2024-0001"),
                file_path="pkg.json",
            ),
        ]
        result = tier2_scan_worker.run_tier2_scan.delay(
            repo_path="/tmp/repo",
            changed_files=[],
            commit_sha="a" * 40,
            repo_url="https://github.com/x/y",
        ).get()
        # Celery em eager mode já fez round-trip JSON, mas validamos
        # estrutura explicitamente.
        assert isinstance(result, list)
        assert isinstance(result[0], dict)
        assert result[0]["cve_id"] == "CVE-2024-0001"
        # severity é string, não Enum
        assert result[0]["severity"] in {"critical", "high", "medium", "low", "info"}
        # id é string (UUID stringificado)
        assert isinstance(result[0]["id"], str)
        # created_at é ISO string
        assert "T" in result[0]["created_at"]


class TestAdapterBehavior:
    def test_semgrep_adapter_dispatches_to_scan_expanded(self):
        """Verifica que ``_SemgrepExpandedAdapter.scan`` realmente
        delega para ``scan_expanded`` e não para ``scan_changed``.
        """
        adapter = tier2_scan_worker._SemgrepExpandedAdapter()
        with patch.object(adapter, "scan_expanded") as expanded, patch.object(
            adapter, "scan_changed"
        ) as changed:
            expanded.return_value = []
            adapter.scan(
                repo_path="/tmp/repo",
                commit_sha="a" * 40,
                repo_url="https://github.com/x/y",
            )
            expanded.assert_called_once()
            changed.assert_not_called()


class TestCeleryRegistration:
    def test_tier2_task_in_registry(self):
        from app.core.celery_app import celery_app

        assert (
            "app.presentation.workers.tier2_scan_worker.run_tier2_scan"
            in celery_app.tasks
        )

    def test_tier2_route(self):
        from app.core.celery_app import celery_app

        routes = celery_app.conf.task_routes
        assert routes["app.presentation.workers.tier2_scan_worker.*"]["queue"] == "tier2"
