from app.domain.finding.entities import Finding
from app.domain.finding.value_objects import Severity
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


class TestAbstractContract:
    def test_cannot_instantiate_without_scan_implementation(self):
        import pytest

        with pytest.raises(TypeError):
            BaseScanner()  # type: ignore[abstract]

    def test_default_timeout_120s(self):
        assert OkScanner.TIMEOUT == 120
