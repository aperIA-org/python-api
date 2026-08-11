from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.domain.finding.value_objects import Severity
from app.infrastructure.scanners.semgrep_scanner import SemgrepScanner


FIXTURES_DIR = Path(__file__).resolve().parents[1] / "fixtures"


def _completed(stdout: str):
    proc = MagicMock()
    proc.stdout = stdout
    proc.returncode = 0
    return proc


@pytest.fixture
def security_audit_json() -> str:
    return (FIXTURES_DIR / "semgrep_security_audit.json").read_text("utf-8")


@pytest.fixture
def auto_with_cve_json() -> str:
    return (FIXTURES_DIR / "semgrep_auto_with_cve.json").read_text("utf-8")


class TestScanChanged:
    def test_scans_whole_tree_when_no_changed_files(self, security_audit_json):
        """Sem diff (scan manual de branch) o alvo passa a ser a árvore inteira.

        Antes este caminho devolvia ``[]`` sem chamar o Semgrep — era o motivo
        de o Tier 1 concluir com zero findings em todo scan manual.
        """
        with patch(
            "app.infrastructure.scanners.semgrep_scanner.subprocess.run",
            return_value=_completed(security_audit_json),
        ) as run_mock:
            findings = SemgrepScanner().scan_changed(
                repo_path="/tmp/repo",
                changed_files=[],
                commit_sha="a" * 40,
                repo_url="https://github.com/x/y",
            )

        run_mock.assert_called_once()
        assert run_mock.call_args.args[0][-1] == "."
        assert len(findings) == 3

    def test_explicit_changed_files_still_scope_the_scan(self, security_audit_json):
        """Com diff, o alvo continua sendo só os arquivos do PR."""
        with patch(
            "app.infrastructure.scanners.semgrep_scanner.subprocess.run",
            return_value=_completed(security_audit_json),
        ) as run_mock:
            SemgrepScanner().scan_changed(
                repo_path="/tmp/repo",
                changed_files=["app/db.py"],
                commit_sha="a" * 40,
                repo_url="https://github.com/x/y",
            )

        cmd = run_mock.call_args.args[0]
        assert cmd[-1] == "app/db.py"
        assert "." not in cmd

    def test_parses_security_audit_results(self, security_audit_json):
        with patch(
            "app.infrastructure.scanners.semgrep_scanner.subprocess.run",
            return_value=_completed(security_audit_json),
        ):
            findings = SemgrepScanner().scan_changed(
                repo_path="/tmp/repo",
                changed_files=["app/db.py", "app/runner.py", "app/util.py"],
                commit_sha="a" * 40,
                repo_url="https://github.com/acme/repo",
            )

        assert len(findings) == 3
        # All should have tier=1
        assert all(f.tier == 1 for f in findings)

        sql = next(f for f in findings if "sql-injection" in f.title)
        assert sql.severity is Severity.HIGH
        assert sql.file_path == "app/db.py"
        assert sql.line_number == 42
        # Só o identificador: a frase completa segue em `raw_output`.
        assert sql.cwe_id == "CWE-89"
        assert sql.cve_id is None

    def test_severity_mapping_warning_to_medium(self, security_audit_json):
        with patch(
            "app.infrastructure.scanners.semgrep_scanner.subprocess.run",
            return_value=_completed(security_audit_json),
        ):
            findings = SemgrepScanner().scan_changed(
                repo_path="/tmp/repo",
                changed_files=["app/runner.py"],
                commit_sha="a" * 40,
                repo_url="https://github.com/x/y",
            )
        warning = next(f for f in findings if "subprocess" in f.title)
        assert warning.severity is Severity.MEDIUM

    def test_severity_mapping_info_to_low(self, security_audit_json):
        with patch(
            "app.infrastructure.scanners.semgrep_scanner.subprocess.run",
            return_value=_completed(security_audit_json),
        ):
            findings = SemgrepScanner().scan_changed(
                repo_path="/tmp/repo",
                changed_files=["app/util.py"],
                commit_sha="a" * 40,
                repo_url="https://github.com/x/y",
            )
        info = next(f for f in findings if "print-statement" in f.title)
        assert info.severity is Severity.LOW

    def test_command_uses_security_audit_config_at_tier1(self, security_audit_json):
        with patch(
            "app.infrastructure.scanners.semgrep_scanner.subprocess.run",
            return_value=_completed(security_audit_json),
        ) as run_mock:
            SemgrepScanner().scan_changed(
                repo_path="/tmp/repo",
                changed_files=["a.py", "b.py"],
                commit_sha="a" * 40,
                repo_url="https://github.com/x/y",
            )

        args = run_mock.call_args[0][0]
        assert args[0] == "semgrep"
        assert "--config=p/security-audit" in args
        assert "--json" in args
        # changed_files appended
        assert "a.py" in args and "b.py" in args
        # cwd usado
        assert run_mock.call_args[1]["cwd"] == "/tmp/repo"

    def test_empty_stdout_returns_empty(self):
        with patch(
            "app.infrastructure.scanners.semgrep_scanner.subprocess.run",
            return_value=_completed(""),
        ):
            findings = SemgrepScanner().scan_changed(
                repo_path="/tmp/repo",
                changed_files=["a.py"],
                commit_sha="a" * 40,
                repo_url="https://github.com/x/y",
            )
        assert findings == []


class TestScanExpanded:
    def test_uses_config_auto_at_tier2(self, auto_with_cve_json):
        with patch(
            "app.infrastructure.scanners.semgrep_scanner.subprocess.run",
            return_value=_completed(auto_with_cve_json),
        ) as run_mock:
            findings = SemgrepScanner().scan_expanded(
                repo_path="/tmp/repo",
                commit_sha="a" * 40,
                repo_url="https://github.com/x/y",
            )

        args = run_mock.call_args[0][0]
        assert "--config=auto" in args
        assert "." in args
        assert all(f.tier == 2 for f in findings)

    def test_extracts_cve_id_when_metadata_has_cve(self, auto_with_cve_json):
        with patch(
            "app.infrastructure.scanners.semgrep_scanner.subprocess.run",
            return_value=_completed(auto_with_cve_json),
        ):
            findings = SemgrepScanner().scan_expanded(
                repo_path="/tmp/repo",
                commit_sha="a" * 40,
                repo_url="https://github.com/x/y",
            )
        log4shell = findings[0]
        assert log4shell.cve_id is not None
        assert str(log4shell.cve_id) == "CVE-2021-44228"

    def test_uses_300s_timeout(self, auto_with_cve_json):
        with patch(
            "app.infrastructure.scanners.semgrep_scanner.subprocess.run",
            return_value=_completed(auto_with_cve_json),
        ) as run_mock:
            SemgrepScanner().scan_expanded(
                repo_path="/tmp/repo",
                commit_sha="a" * 40,
                repo_url="https://github.com/x/y",
            )
        assert run_mock.call_args[1]["timeout"] == 300


class TestScanDispatch:
    def test_scan_dispatches_to_scan_changed(self, security_audit_json):
        with patch(
            "app.infrastructure.scanners.semgrep_scanner.subprocess.run",
            return_value=_completed(security_audit_json),
        ):
            findings = SemgrepScanner().scan(
                repo_path="/tmp/repo",
                changed_files=["app/db.py"],
                commit_sha="a" * 40,
                repo_url="https://github.com/x/y",
            )
        assert all(f.tier == 1 for f in findings)


def test_cwe_longo_do_semgrep_cabe_na_coluna():
    """Regressão: o CWE real do Semgrep estourava `VARCHAR(50)`.

    O Semgrep devolve `metadata["cwe"]` como LISTA de frases descritivas. O
    valor real que quebrou a persistência em produção tem 93 caracteres, e as
    fixtures usavam uma versão curta (21) que cabia — por isso nenhum teste
    pegava. Aqui o valor é o real.
    """
    from app.infrastructure.scanners.semgrep_scanner import _normalizar_cwe

    real = [
        "CWE-79: Improper Neutralization of Input During Web Page "
        "Generation ('Cross-site Scripting')"
    ]
    assert len(real[0]) > 50
    normalizado = _normalizar_cwe(real)
    assert normalizado == "CWE-79"
    assert len(normalizado) <= 50


def test_cwe_ausente_ou_vazio_vira_none():
    from app.infrastructure.scanners.semgrep_scanner import _normalizar_cwe

    assert _normalizar_cwe(None) is None
    assert _normalizar_cwe([]) is None
    assert _normalizar_cwe("") is None


def test_cwe_sem_identificador_e_truncado():
    """Formato inesperado não pode voltar a estourar a coluna."""
    from app.infrastructure.scanners.semgrep_scanner import _normalizar_cwe

    esquisito = "descricao sem identificador " * 10
    assert len(_normalizar_cwe(esquisito)) <= 50
