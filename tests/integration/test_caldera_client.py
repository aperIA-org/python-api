from unittest.mock import MagicMock, patch

import httpx
import pytest
import respx

from core.exceptions import SandboxViolationError


def _make_client():
    """Instancia MitreCalderaClient sem verificar settings nem conectar."""
    from infrastructure.intelligence.mitre_caldera_client import MitreCalderaClient

    with patch(
        "infrastructure.intelligence.mitre_caldera_client.settings"
    ) as mock_settings:
        mock_settings.CALDERA_SANDBOX_MODE = True
        mock_settings.CALDERA_URL = "http://caldera-test:8888"
        mock_settings.CALDERA_API_KEY = "test-api-key"
        mock_settings.CALDERA_AGENT_GROUP = "aperia-sandbox"
        client = MitreCalderaClient()

    return client


class TestSandboxEnforcement:
    def test_raises_when_sandbox_disabled(self):
        from infrastructure.intelligence.mitre_caldera_client import MitreCalderaClient

        with patch(
            "infrastructure.intelligence.mitre_caldera_client.settings"
        ) as mock_settings:
            mock_settings.CALDERA_SANDBOX_MODE = False
            with pytest.raises(SandboxViolationError):
                MitreCalderaClient()


class TestParseResults:
    def test_parse_all_successful(self):
        client = _make_client()
        op = {
            "state": "finished",
            "chain": [
                {"status": 0, "ability": {"technique_id": "T1190"}},
                {"status": 0, "ability": {"technique_id": "T1021"}},
            ],
        }
        result = client._parse_results(op)

        assert result["techniques_executed"] == 2
        assert result["techniques_successful"] == 2
        assert result["success_rate"] == 1.0
        assert result["caldera_validated"] is True
        assert "T1190" in result["ttps_used"]

    def test_parse_partial_success(self):
        client = _make_client()
        op = {
            "state": "finished",
            "chain": [
                {"status": 0, "ability": {"technique_id": "T1190"}},
                {"status": -2, "ability": {"technique_id": "T1021"}},
            ],
        }
        result = client._parse_results(op)

        assert result["techniques_executed"] == 2
        assert result["techniques_successful"] == 1
        assert result["success_rate"] == 0.5

    def test_parse_empty_chain(self):
        client = _make_client()
        op = {"state": "finished", "chain": []}
        result = client._parse_results(op)

        assert result["success_rate"] == 0.0
        assert result["caldera_validated"] is False

    def test_parse_all_failed(self):
        client = _make_client()
        op = {
            "state": "finished",
            "chain": [{"status": -2, "ability": {"technique_id": "T1190"}}],
        }
        result = client._parse_results(op)

        assert result["caldera_validated"] is False
        assert result["success_rate"] == 0.0


class TestRunEmulation:
    @respx.mock
    def test_full_operation_lifecycle(self):
        respx.post("http://caldera-test:8888/api/v2/adversaries").mock(
            return_value=httpx.Response(200, json={"id": "adv-abc123"})
        )
        respx.get("http://caldera-test:8888/api/v2/abilities").mock(
            return_value=httpx.Response(200, json=[{"ability_id": "ab-001"}])
        )
        respx.post("http://caldera-test:8888/api/v2/operations").mock(
            return_value=httpx.Response(200, json={"id": "op-xyz789"})
        )
        respx.get("http://caldera-test:8888/api/v2/operations/op-xyz789").mock(
            return_value=httpx.Response(
                200,
                json={
                    "state": "finished",
                    "chain": [
                        {"status": 0, "ability": {"technique_id": "T1190"}}
                    ],
                },
            )
        )

        client = _make_client()
        result = client.run_emulation(["T1190"], commit_sha="abc12345")

        assert result["caldera_validated"] is True
        assert result["success_rate"] == 1.0
        assert result["techniques_executed"] == 1
