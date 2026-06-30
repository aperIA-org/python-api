"""Testes do MITRE Caldera client.

Cobertura obrigatória (Semana 10):

- Sandbox bypass → ``SandboxViolationError`` no ``__init__``
- Happy path: create_adversary → run_operation → await_results
- **Timeout** (operação que não finaliza) → ``run_safe`` retorna
  ``status="failed"`` com ``reason="timeout"``
- DEBT comment de ``_map_to_abilities`` presente no source
"""
from __future__ import annotations

import inspect

import httpx
import pytest
import respx

from app.config import settings
from app.core.exceptions import SandboxViolationError
from app.infrastructure.intelligence import mitre_caldera_client
from app.infrastructure.intelligence.mitre_caldera_client import CalderaClient


_BASE_URL = "http://caldera:8888"


def _build_client(poll_interval: int = 0) -> CalderaClient:
    return CalderaClient(
        poll_interval=poll_interval,
        http_client=httpx.Client(base_url=_BASE_URL, timeout=5.0, headers={"KEY": "test-key"}),
    )


# -----------------------------------------------------------------------------
# Sandbox invariant
# -----------------------------------------------------------------------------


class TestSandboxInvariant:
    def test_constructor_raises_when_sandbox_disabled(self, monkeypatch):
        monkeypatch.setattr(settings, "CALDERA_SANDBOX_MODE", False)
        with pytest.raises(SandboxViolationError, match="sandbox"):
            CalderaClient(poll_interval=0)

    def test_constructor_ok_when_sandbox_enabled(self):
        # Settings default já é True; só garante que construir não levanta
        client = CalderaClient(poll_interval=0)
        assert client.MAX_WAIT == 600


# -----------------------------------------------------------------------------
# Happy path
# -----------------------------------------------------------------------------


class TestHappyPath:
    @respx.mock
    def test_full_pipeline_returns_metrics(self):
        respx.post(f"{_BASE_URL}/api/v2/adversaries").mock(
            return_value=httpx.Response(200, json={"id": "adv-1"})
        )
        respx.post(f"{_BASE_URL}/api/v2/operations").mock(
            return_value=httpx.Response(200, json={"id": "op-1"})
        )
        respx.get(f"{_BASE_URL}/api/v2/operations/op-1").mock(
            return_value=httpx.Response(
                200,
                json={
                    "state": "finished",
                    "chain": [
                        {"status": 0, "ability": {"technique_id": "T1190"}},
                        {"status": 0, "ability": {"technique_id": "T1059"}},
                        {"status": 1, "ability": {"technique_id": "T1078"}},
                    ],
                },
            )
        )

        client = _build_client()
        result = client.run_safe(
            adversary_name="log4shell-poc",
            mitre_techniques=["T1190", "T1059"],
        )

        assert result["status"] == "ok"
        assert result["techniques_executed"] == 3
        assert result["techniques_successful"] == 2
        assert result["success_rate"] == pytest.approx(2 / 3)
        assert result["caldera_validated"] is True
        assert result["ttps_used"] == ["T1190", "T1059", "T1078"]

    @respx.mock
    def test_zero_successful_yields_caldera_validated_false(self):
        respx.post(f"{_BASE_URL}/api/v2/adversaries").mock(
            return_value=httpx.Response(200, json={"id": "adv-1"})
        )
        respx.post(f"{_BASE_URL}/api/v2/operations").mock(
            return_value=httpx.Response(200, json={"id": "op-1"})
        )
        respx.get(f"{_BASE_URL}/api/v2/operations/op-1").mock(
            return_value=httpx.Response(
                200,
                json={
                    "state": "finished",
                    "chain": [
                        {"status": 1, "ability": {"technique_id": "T1190"}}
                    ],
                },
            )
        )
        client = _build_client()
        result = client.run_safe("x", ["T1190"])
        assert result["status"] == "ok"
        assert result["caldera_validated"] is False
        assert result["success_rate"] == 0.0

    @respx.mock
    def test_create_adversary_payload(self):
        route = respx.post(f"{_BASE_URL}/api/v2/adversaries").mock(
            return_value=httpx.Response(200, json={"id": "adv-9"})
        )
        client = _build_client()
        adv_id = client.create_adversary("my-adv", ["T1190"])
        assert adv_id == "adv-9"

        sent = route.calls.last.request
        body = sent.content.decode()
        # nome do adversário prefixado com aperia-
        assert "aperia-my-adv" in body
        assert "sandbox" in body  # description

    @respx.mock
    def test_run_operation_uses_settings_agent_group(self, monkeypatch):
        monkeypatch.setattr(settings, "CALDERA_AGENT_GROUP", "blue-team")
        route = respx.post(f"{_BASE_URL}/api/v2/operations").mock(
            return_value=httpx.Response(200, json={"id": "op-7"})
        )
        client = _build_client()
        client.run_operation("adv-abc")
        body = route.calls.last.request.content.decode()
        assert "blue-team" in body


# -----------------------------------------------------------------------------
# Timeout — obrigatório (decisão #1 Semana 10)
# -----------------------------------------------------------------------------


class TestTimeout:
    @respx.mock
    def test_await_results_raises_timeout_when_never_finishes(self):
        respx.get(f"{_BASE_URL}/api/v2/operations/op-stuck").mock(
            return_value=httpx.Response(200, json={"state": "running", "chain": []})
        )
        # poll_interval=1 + MAX_WAIT=600 → 600 iterações. Para teste,
        # forçamos um MAX_WAIT pequeno via monkeypatch.
        client = _build_client(poll_interval=1)
        client.MAX_WAIT = 2  # 2 iterações apenas
        with pytest.raises(TimeoutError, match="op-stuck"):
            client.await_results("op-stuck")

    @respx.mock
    def test_run_safe_timeout_returns_status_failed(self):
        """Cenário obrigatório do checklist Semana 10."""
        respx.post(f"{_BASE_URL}/api/v2/adversaries").mock(
            return_value=httpx.Response(200, json={"id": "adv-1"})
        )
        respx.post(f"{_BASE_URL}/api/v2/operations").mock(
            return_value=httpx.Response(200, json={"id": "op-stuck"})
        )
        respx.get(f"{_BASE_URL}/api/v2/operations/op-stuck").mock(
            return_value=httpx.Response(200, json={"state": "running", "chain": []})
        )

        client = _build_client(poll_interval=1)
        client.MAX_WAIT = 2

        result = client.run_safe("op", ["T1190"])
        assert result["status"] == "failed"
        assert result["reason"] == "timeout"
        assert result["caldera_validated"] is False
        assert result["success_rate"] == 0.0
        assert result["ttps_used"] == []


# -----------------------------------------------------------------------------
# Fault isolation — qualquer erro vira status="failed"
# -----------------------------------------------------------------------------


class TestFaultIsolation:
    @respx.mock
    def test_create_adversary_500_yields_failed_status(self):
        respx.post(f"{_BASE_URL}/api/v2/adversaries").mock(
            return_value=httpx.Response(500)
        )
        result = _build_client().run_safe("op", ["T1190"])
        assert result["status"] == "failed"
        assert result["caldera_validated"] is False

    @respx.mock
    def test_run_operation_connection_error_yields_failed(self):
        respx.post(f"{_BASE_URL}/api/v2/adversaries").mock(
            return_value=httpx.Response(200, json={"id": "adv-1"})
        )
        respx.post(f"{_BASE_URL}/api/v2/operations").mock(
            side_effect=httpx.ConnectError("Connection refused")
        )
        result = _build_client().run_safe("op", ["T1190"])
        assert result["status"] == "failed"
        assert result["reason"] == "ConnectError"

    @respx.mock
    def test_await_results_500_yields_failed(self):
        respx.post(f"{_BASE_URL}/api/v2/adversaries").mock(
            return_value=httpx.Response(200, json={"id": "adv-1"})
        )
        respx.post(f"{_BASE_URL}/api/v2/operations").mock(
            return_value=httpx.Response(200, json={"id": "op-x"})
        )
        respx.get(f"{_BASE_URL}/api/v2/operations/op-x").mock(
            return_value=httpx.Response(500)
        )
        result = _build_client().run_safe("op", ["T1190"])
        assert result["status"] == "failed"


# -----------------------------------------------------------------------------
# _map_to_abilities DEBT
# -----------------------------------------------------------------------------


class TestMapToAbilitiesDebt:
    def test_returns_empty_list_in_mvp(self):
        client = _build_client()
        assert client._map_to_abilities(["T1190", "T1059"]) == []

    def test_debt_comment_documents_impact(self):
        source = inspect.getsource(
            mitre_caldera_client.CalderaClient._map_to_abilities
        )
        assert "DEBT" in source
        assert "caldera_validated" in source
        # Impacto observável documentado conforme decisão #2
        assert "False" in source or "false" in source


# -----------------------------------------------------------------------------
# Parser de resultados
# -----------------------------------------------------------------------------


class TestParseResults:
    def test_empty_chain_returns_zero_metrics(self):
        client = _build_client()
        result = client._parse_results({"chain": []})
        assert result["techniques_executed"] == 0
        assert result["success_rate"] == 0.0
        assert result["caldera_validated"] is False
        assert result["ttps_used"] == []

    def test_missing_chain_key_handled(self):
        client = _build_client()
        result = client._parse_results({"state": "finished"})
        assert result["techniques_executed"] == 0
