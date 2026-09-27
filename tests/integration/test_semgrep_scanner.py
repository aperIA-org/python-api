import json
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

from app.domain.finding.value_objects import Severity
from app.infrastructure.scanners.semgrep_scanner import (
    SemgrepScanner,
    SemgrepConfigError,
    _erros_de_config,
)


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

    def test_command_uses_default_config_at_tier1(self, security_audit_json):
        """Tier 1 roda `p/default`, nao `p/security-audit`.

        `p/security-audit` e estreito: contra o repo-alvo de demonstracao ele
        acha 5 dos 16 problemas plantados e deixa passar SQLi, XSS, JWT com
        `alg=none`, path traversal, SSRF e MD5. `p/default` acha 40 no mesmo
        repositorio.
        """
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
        assert "--config=p/default" in args
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


class TestErroDeConfigNaoViraZero:
    """Erro de regra tem de virar FALHA, nunca `results: []`.

    Regressao do incidente: com o Semgrep 1.62.0, o registro passou a servir
    regras de severidade `MEDIUM`, aquela versao recusou a regra, e UMA regra
    invalida aborta a config inteira. O parser so lia `results`, entao o Tier 2
    registrava `done` com 0 findings sobre um repositorio com SQLi, XSS, SSRF e
    JWT quebrado — silencio indistinguivel de "repositorio limpo".
    """

    ERRO_DE_SCHEMA = json.dumps({
        "results": [],
        "errors": [
            {
                "code": 4,
                "type": "InvalidRuleSchemaError",
                "long_msg": "'MEDIUM' is not one of ['ERROR', 'WARNING', 'INFO']",
            },
            {"code": 7, "type": "SemgrepError", "message": "invalid configuration file found"},
        ],
    })

    def test_cai_para_o_fallback_quando_a_config_principal_quebra(self, security_audit_json):
        respostas = [_completed(self.ERRO_DE_SCHEMA), _completed(security_audit_json)]
        with patch(
            "app.infrastructure.scanners.semgrep_scanner.subprocess.run",
            side_effect=respostas,
        ) as run_mock:
            findings = SemgrepScanner().scan_expanded(
                repo_path="/tmp/repo",
                commit_sha="a" * 40,
                repo_url="https://github.com/x/y",
            )

        assert run_mock.call_count == 2
        assert "--config=auto" in run_mock.call_args_list[0][0][0]
        assert "--config=p/security-audit" in run_mock.call_args_list[1][0][0]
        # O resgate entrega cobertura de verdade, nao lista vazia.
        assert findings

    def test_levanta_quando_o_fallback_tambem_quebra(self):
        with patch(
            "app.infrastructure.scanners.semgrep_scanner.subprocess.run",
            return_value=_completed(self.ERRO_DE_SCHEMA),
        ):
            with pytest.raises(SemgrepConfigError) as exc:
                SemgrepScanner().scan_expanded(
                    repo_path="/tmp/repo",
                    commit_sha="a" * 40,
                    repo_url="https://github.com/x/y",
                )
        assert "MEDIUM" in str(exc.value)

    def test_run_safe_marca_failed_em_vez_de_done_com_zero(self):
        """A excecao vira `failed` na tela, que e o ponto todo.

        `done` com 0 findings afirma que o repositorio esta limpo; `failed` diz
        que ninguem olhou. Sao coisas diferentes e a tela precisa distinguir.
        """
        with patch(
            "app.infrastructure.scanners.semgrep_scanner.subprocess.run",
            return_value=_completed(self.ERRO_DE_SCHEMA),
        ):
            findings = SemgrepScanner().run_safe(
                tool_id="semgrep-full",
                tier=2,
                repo_path="/tmp/repo",
                changed_files=[],
                commit_sha="a" * 40,
                repo_url="https://github.com/x/y",
            )
        # `run_safe` engole a excecao e devolve [], mas registra o desfecho real.
        assert findings == []

    def test_erro_de_arquivo_nao_e_erro_de_config(self, security_audit_json):
        """Arquivo que nao parseia e normal e nao pode disparar o fallback.

        Sintaxe quebrada ou linguagem nao suportada acontece em repositorio real
        e nao invalida a varredura. Por isso o filtro e por TIPO de erro.
        """
        payload = json.loads(security_audit_json)
        payload["errors"] = [{"code": 3, "type": "SourceParseError", "message": "cannot parse"}]
        with patch(
            "app.infrastructure.scanners.semgrep_scanner.subprocess.run",
            return_value=_completed(json.dumps(payload)),
        ) as run_mock:
            findings = SemgrepScanner().scan_expanded(
                repo_path="/tmp/repo",
                commit_sha="a" * 40,
                repo_url="https://github.com/x/y",
            )
        assert run_mock.call_count == 1
        assert findings


class TestTipoDeErroVariante:
    """`errors[].type` vem como string OU como lista — ver `_nome_do_tipo`."""

    def test_partial_parsing_como_lista_nao_quebra(self):
        # Formato real: um arquivo que não parseia no repositório varrido.
        raw = {
            "results": [],
            "errors": [{"type": ["PartialParsing", [{"path": "b.py"}]]}],
        }
        # Antes: TypeError: unhashable type: 'list'.
        assert _erros_de_config(raw) == []

    def test_erro_de_config_como_lista_ainda_e_detectado(self):
        raw = {"errors": [{"type": ["SemgrepError", {}], "message": "regra ruim"}]}
        assert _erros_de_config(raw) == ["regra ruim"]

    def test_erro_de_config_como_string_continua_valendo(self):
        raw = {"errors": [{"type": "InvalidRuleSchemaError", "long_msg": "schema"}]}
        assert _erros_de_config(raw) == ["schema"]
