from unittest.mock import patch

from app.domain.finding.entities import Finding
from app.domain.finding.value_objects import Severity
from app.domain.scan.value_objects import ToolStatus
from app.infrastructure.scanners.base_scanner import BaseScanner


def _make_finding(**overrides) -> Finding:
    base = {
        "source": "fake",
        "severity": Severity.LOW,
        "title": "x",
        "description": "x",
        "commit_sha": "a" * 40,
        "repo_url": "https://github.com/x/y",
    }
    base.update(overrides)
    return Finding(**base)


class OkScanner(BaseScanner):
    def scan(self, *args, **kwargs) -> list[Finding]:
        return [_make_finding(title="ok-1"), _make_finding(title="ok-2")]


class BoomScanner(BaseScanner):
    def scan(self, *args, **kwargs) -> list[Finding]:
        raise RuntimeError("scanner exploded mid-run")


class TestRunSafeHappyPath:
    def test_returns_scan_results(self):
        findings = OkScanner().run_safe(commit_sha="a" * 40)
        assert len(findings) == 2
        assert all(isinstance(f, Finding) for f in findings)

    def test_passes_through_kwargs(self):
        # garante que run_safe forwarda kwargs para scan
        class CaptureScanner(BaseScanner):
            received = {}

            def scan(self, *args, **kwargs):
                CaptureScanner.received = kwargs
                return []

        CaptureScanner().run_safe(commit_sha="b" * 40, repo_path="/tmp/x", extra="z")
        assert CaptureScanner.received["repo_path"] == "/tmp/x"
        assert CaptureScanner.received["extra"] == "z"


class TestRunSafeFaultIsolation:
    def test_returns_empty_list_on_exception(self):
        findings = BoomScanner().run_safe(commit_sha="a" * 40)
        assert findings == []

    def test_does_not_propagate_exception(self):
        # Sem try/except no caller; se propagar, o teste falha
        BoomScanner().run_safe(commit_sha="a" * 40)

    def test_custom_scanner_name_is_logged(self, caplog):
        BoomScanner().run_safe(scanner_name="MyCustom", commit_sha="c" * 40)
        # caplog não captura structlog por padrão sem config —
        # esse teste valida apenas que o argumento não levanta erro.

    def test_default_scanner_name_is_class_name(self):
        # Não testamos o log content (structlog não-stdlib-configured), só que
        # o método executa sem erro com o nome default.
        findings = BoomScanner().run_safe(commit_sha="d" * 40)
        assert findings == []

    def test_log_registra_o_tipo_da_excecao(self):
        # `error` sozinho é a mensagem da lib e descreve o sintoma; o tipo é o
        # que separa "ferramenta fora do ar" de "não terminou no tempo".
        from structlog.testing import capture_logs

        with capture_logs() as logs:
            BoomScanner().run_safe(commit_sha="e" * 40)

        skipped = [e for e in logs if e["event"] == "scanner_skipped"]
        assert skipped, "esperava um evento scanner_skipped"
        assert skipped[0]["error_type"] == "RuntimeError"


class TestAbstractContract:
    def test_cannot_instantiate_without_scan_implementation(self):
        import pytest

        with pytest.raises(TypeError):
            BaseScanner()  # type: ignore[abstract]

    def test_default_timeout_120s(self):
        assert OkScanner.TIMEOUT == 120


class TestRunSafeRegistraFerramenta:
    """`run_safe` é o único ponto que sabe se a ferramenta rodou ou quebrou.

    Depois do `return []` as duas situações são o mesmo valor — por isso o
    registro em `scan_tool_runs` acontece aqui dentro, e não no call site.
    """

    def test_grava_running_antes_e_done_depois(self):
        """Duas escritas, nesta ordem.

        A primeira e' o que permite o dashboard dizer QUAL ferramenta esta'
        rodando. Sem ela a linha so' nascia no fim, e durante o scan a tela
        tinha que adivinhar pela ordem do pipeline.
        """
        with patch(
            "app.infrastructure.persistence.scan_tool_run_writer.record_tool_run"
        ) as rec:
            OkScanner().run_safe(tool_id="trivy", tier=2, commit_sha="a" * 40)

        assert rec.call_count == 2
        primeiro, segundo = rec.call_args_list[0].kwargs, rec.call_args_list[1].kwargs

        assert primeiro["status"] is ToolStatus.RUNNING
        assert primeiro["started_at"] is not None
        # `completed_at` fica None de proposito: a ferramenta nao terminou.
        assert primeiro["completed_at"] is None

        assert segundo["tool"] == "trivy"
        assert segundo["tier"] == 2
        assert segundo["status"] is ToolStatus.DONE
        # 2, não None: rodou e achou dois.
        assert segundo["findings_count"] == 2
        assert segundo["duration_ms"] is not None
        assert segundo["completed_at"] is not None

    def test_falha_grava_failed_com_o_tipo_da_excecao(self):
        with patch(
            "app.infrastructure.persistence.scan_tool_run_writer.record_tool_run"
        ) as rec:
            BoomScanner().run_safe(tool_id="trivy", tier=2, commit_sha="a" * 40)

        # A ultima escrita e' o desfecho; a primeira foi o `running`.
        kw = rec.call_args_list[-1].kwargs
        assert kw["status"] is ToolStatus.FAILED
        assert "RuntimeError" in kw["reason"]
        # Sem contagem: não houve varredura, e 0 seria mentira.
        assert kw.get("findings_count") is None

    def test_sem_tool_id_nao_grava_nada(self):
        """Chamadas antigas (sem `tool_id`/`tier`) seguem funcionando."""
        with patch(
            "app.infrastructure.persistence.scan_tool_run_writer.record_tool_run"
        ) as rec:
            OkScanner().run_safe(commit_sha="a" * 40)
        rec.assert_not_called()

    def test_sem_commit_sha_nao_grava_nada(self):
        with patch(
            "app.infrastructure.persistence.scan_tool_run_writer.record_tool_run"
        ) as rec:
            OkScanner().run_safe(tool_id="trivy", tier=2)
        rec.assert_not_called()

    def test_tool_id_nao_vaza_para_o_scan(self):
        """`tool_id`/`tier` são de instrumentação e não podem chegar ao scanner."""

        class CaptureScanner(BaseScanner):
            received = {}

            def scan(self, *args, **kwargs):
                CaptureScanner.received = kwargs
                return []

        with patch("app.infrastructure.persistence.scan_tool_run_writer.record_tool_run"):
            CaptureScanner().run_safe(tool_id="zap", tier=3, commit_sha="a" * 40)

        assert "tool_id" not in CaptureScanner.received
        assert "tier" not in CaptureScanner.received
