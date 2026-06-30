"""Testes do ZAPScanner com respx.

ZAP via REST API usa ``httpx`` no client, então ``respx`` é o mock
nativo. Cada teste injeta ``poll_interval=0`` para evitar
``time.sleep`` real durante o polling.

A decisão #1 da Semana 9 fixou ``target_url="http://localhost:8080/app"``
como alvo simulado nos testes.
"""
from __future__ import annotations

import httpx
import pytest
import respx

from app.domain.finding.value_objects import Severity
from app.infrastructure.scanners.zap_scanner import ZAPScanner


_ZAP_URL = "http://zap:8090"
_TARGET = "http://localhost:8080/app"


def _build_scanner() -> ZAPScanner:
    # Usa httpx.Client com timeout curto e poll_interval=0 (sem sleep)
    return ZAPScanner(
        zap_url=_ZAP_URL,
        api_key="test-key",
        poll_interval=0,
        max_wait=5,
        http_client=httpx.Client(timeout=5.0),
    )


_ALERTS_RESPONSE_SAMPLE = {
    "alerts": [
        {
            "name": "SQL Injection",
            "risk": "High",
            "description": "SQLi found in parameter 'id'.",
            "url": "http://localhost:8080/app/login?id=1",
            "cweid": "89",
        },
        {
            "name": "Cross Site Scripting (Reflected)",
            "risk": "High",
            "description": "Reflected XSS.",
            "url": "http://localhost:8080/app/search",
            "cweid": "79",
        },
        {
            "name": "Cookie No HttpOnly Flag",
            "risk": "Low",
            "description": "Cookie without HttpOnly.",
            "url": "http://localhost:8080/app/",
            "cweid": "1004",
        },
        {
            "name": "Information disclosure",
            "risk": "Informational",
            "description": "Server header leaks version.",
            "url": "http://localhost:8080/app/health",
        },
    ]
}


def _mock_full_scan(alerts_payload: dict | None = None) -> None:
    """Configura respx para um scan completo bem-sucedido.

    Sem ``@respx.mock`` aqui — o helper apenas registra rotas no
    router ativo (criado pelo decorator do teste chamador).
    """
    respx.get(f"{_ZAP_URL}/JSON/spider/action/scan/").mock(
        return_value=httpx.Response(200, json={"scan": "1"})
    )
    respx.get(f"{_ZAP_URL}/JSON/spider/view/status/").mock(
        return_value=httpx.Response(200, json={"status": "100"})
    )
    respx.get(f"{_ZAP_URL}/JSON/ascan/action/scan/").mock(
        return_value=httpx.Response(200, json={"scan": "1"})
    )
    respx.get(f"{_ZAP_URL}/JSON/ascan/view/status/").mock(
        return_value=httpx.Response(200, json={"status": "100"})
    )
    respx.get(f"{_ZAP_URL}/JSON/alert/view/alerts/").mock(
        return_value=httpx.Response(
            200, json=alerts_payload or _ALERTS_RESPONSE_SAMPLE
        )
    )


# -----------------------------------------------------------------------------
# Happy path
# -----------------------------------------------------------------------------


class TestFullScanFlow:
    @respx.mock
    def test_full_scan_returns_findings(self):
        _mock_full_scan()
        scanner = _build_scanner()

        findings = scanner.scan(
            target_url=_TARGET,
            commit_sha="a" * 40,
            repo_url="https://github.com/acme/repo",
        )

        assert len(findings) == 4
        assert all(f.source == "zap" for f in findings)
        assert all(f.tier == 3 for f in findings)

    @respx.mock
    def test_severity_mapping_zap_risks(self):
        _mock_full_scan()
        scanner = _build_scanner()

        findings = scanner.scan(
            target_url=_TARGET,
            commit_sha="a" * 40,
            repo_url="https://github.com/acme/repo",
        )

        by_name = {f.title: f.severity for f in findings}
        assert by_name["SQL Injection"] is Severity.HIGH
        assert by_name["Cookie No HttpOnly Flag"] is Severity.LOW
        assert by_name["Information disclosure"] is Severity.INFO

    @respx.mock
    def test_cwe_id_extracted_when_present(self):
        _mock_full_scan()
        scanner = _build_scanner()

        findings = scanner.scan(
            target_url=_TARGET,
            commit_sha="a" * 40,
            repo_url="https://github.com/acme/repo",
        )
        sqli = next(f for f in findings if f.title == "SQL Injection")
        assert sqli.cwe_id == "89"

    @respx.mock
    def test_target_url_passed_to_actions(self):
        spider_route = respx.get(f"{_ZAP_URL}/JSON/spider/action/scan/").mock(
            return_value=httpx.Response(200, json={"scan": "1"})
        )
        respx.get(f"{_ZAP_URL}/JSON/spider/view/status/").mock(
            return_value=httpx.Response(200, json={"status": "100"})
        )
        respx.get(f"{_ZAP_URL}/JSON/ascan/action/scan/").mock(
            return_value=httpx.Response(200, json={"scan": "1"})
        )
        respx.get(f"{_ZAP_URL}/JSON/ascan/view/status/").mock(
            return_value=httpx.Response(200, json={"status": "100"})
        )
        respx.get(f"{_ZAP_URL}/JSON/alert/view/alerts/").mock(
            return_value=httpx.Response(200, json={"alerts": []})
        )
        scanner = _build_scanner()

        scanner.scan(target_url=_TARGET, commit_sha="a" * 40, repo_url="x")

        sent = spider_route.calls.last.request
        assert sent.url.params["url"] == _TARGET
        assert sent.url.params["apikey"] == "test-key"


# -----------------------------------------------------------------------------
# Polling: status progride de 0 → 100
# -----------------------------------------------------------------------------


class TestPollingProgress:
    @respx.mock
    def test_status_eventually_reaches_100(self):
        respx.get(f"{_ZAP_URL}/JSON/spider/action/scan/").mock(
            return_value=httpx.Response(200, json={"scan": "1"})
        )
        respx.get(f"{_ZAP_URL}/JSON/spider/view/status/").mock(
            side_effect=[
                httpx.Response(200, json={"status": "0"}),
                httpx.Response(200, json={"status": "50"}),
                httpx.Response(200, json={"status": "100"}),
            ]
        )
        respx.get(f"{_ZAP_URL}/JSON/ascan/action/scan/").mock(
            return_value=httpx.Response(200, json={"scan": "1"})
        )
        respx.get(f"{_ZAP_URL}/JSON/ascan/view/status/").mock(
            return_value=httpx.Response(200, json={"status": "100"})
        )
        respx.get(f"{_ZAP_URL}/JSON/alert/view/alerts/").mock(
            return_value=httpx.Response(200, json={"alerts": []})
        )

        scanner = _build_scanner()
        scanner.scan(target_url=_TARGET, commit_sha="a" * 40, repo_url="x")
        # Não deve levantar nem hangar

    @respx.mock
    def test_timeout_when_scan_never_completes(self):
        respx.get(f"{_ZAP_URL}/JSON/spider/action/scan/").mock(
            return_value=httpx.Response(200, json={"scan": "1"})
        )
        # status sempre 0 — polling jamais converge
        respx.get(f"{_ZAP_URL}/JSON/spider/view/status/").mock(
            return_value=httpx.Response(200, json={"status": "0"})
        )

        scanner = ZAPScanner(
            zap_url=_ZAP_URL,
            api_key="test-key",
            poll_interval=0,
            max_wait=2,  # estoura cedo
            http_client=httpx.Client(timeout=5.0),
        )
        with pytest.raises(TimeoutError, match="spider"):
            scanner.scan(target_url=_TARGET, commit_sha="a" * 40, repo_url="x")


# -----------------------------------------------------------------------------
# Fault isolation via BaseScanner.run_safe
# -----------------------------------------------------------------------------


class TestFaultIsolation:
    @respx.mock
    def test_run_safe_returns_empty_when_zap_returns_500(self):
        respx.get(f"{_ZAP_URL}/JSON/spider/action/scan/").mock(
            return_value=httpx.Response(500, text="oops")
        )
        scanner = _build_scanner()

        findings = scanner.run_safe(
            target_url=_TARGET, commit_sha="a" * 40, repo_url="x"
        )
        assert findings == []

    @respx.mock
    def test_run_safe_returns_empty_when_connection_refused(self):
        respx.get(f"{_ZAP_URL}/JSON/spider/action/scan/").mock(
            side_effect=httpx.ConnectError("Connection refused")
        )
        scanner = _build_scanner()

        findings = scanner.run_safe(
            target_url=_TARGET, commit_sha="a" * 40, repo_url="x"
        )
        assert findings == []

    @respx.mock
    def test_run_safe_returns_empty_when_alert_view_500(self):
        respx.get(f"{_ZAP_URL}/JSON/spider/action/scan/").mock(
            return_value=httpx.Response(200, json={"scan": "1"})
        )
        respx.get(f"{_ZAP_URL}/JSON/spider/view/status/").mock(
            return_value=httpx.Response(200, json={"status": "100"})
        )
        respx.get(f"{_ZAP_URL}/JSON/ascan/action/scan/").mock(
            return_value=httpx.Response(200, json={"scan": "1"})
        )
        respx.get(f"{_ZAP_URL}/JSON/ascan/view/status/").mock(
            return_value=httpx.Response(200, json={"status": "100"})
        )
        respx.get(f"{_ZAP_URL}/JSON/alert/view/alerts/").mock(
            return_value=httpx.Response(500)
        )
        scanner = _build_scanner()
        findings = scanner.run_safe(
            target_url=_TARGET, commit_sha="a" * 40, repo_url="x"
        )
        assert findings == []


# -----------------------------------------------------------------------------
# Empty / edge cases
# -----------------------------------------------------------------------------


class TestEdgeCases:
    @respx.mock
    def test_no_alerts_returns_empty_list(self):
        _mock_full_scan(alerts_payload={"alerts": []})
        scanner = _build_scanner()

        findings = scanner.scan(
            target_url=_TARGET, commit_sha="a" * 40, repo_url="x"
        )
        assert findings == []

    @respx.mock
    def test_unknown_risk_defaults_to_low(self):
        _mock_full_scan(
            alerts_payload={
                "alerts": [
                    {
                        "name": "Mystery",
                        "risk": "UnknownLevel",  # não está no _RISK_MAP
                        "url": "x",
                    }
                ]
            }
        )
        scanner = _build_scanner()

        findings = scanner.scan(
            target_url=_TARGET, commit_sha="a" * 40, repo_url="x"
        )
        assert findings[0].severity is Severity.LOW

    @respx.mock
    def test_alert_without_cweid_keeps_none(self):
        _mock_full_scan(
            alerts_payload={
                "alerts": [{"name": "X", "risk": "Low", "url": "y"}]
            }
        )
        scanner = _build_scanner()
        findings = scanner.scan(
            target_url=_TARGET, commit_sha="a" * 40, repo_url="x"
        )
        assert findings[0].cwe_id is None
