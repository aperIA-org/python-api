from unittest.mock import MagicMock, patch

import pytest

from core.exceptions import CTIEnrichmentError


def _make_client():
    """Instancia OpenCTIClient sem tentar conectar ao servidor."""
    from infrastructure.intelligence.opencti_client import OpenCTIClient

    client = object.__new__(OpenCTIClient)
    client.client = MagicMock()
    return client


def _cve_response(cve_id: str, ttps: list[str], cvss: float) -> dict:
    return {
        "vulnerabilities": {
            "edges": [
                {
                    "node": {
                        "name": cve_id,
                        "x_opencti_cvss_base_score": cvss,
                        "stixCoreRelationships": {
                            "edges": [
                                {
                                    "node": {
                                        "relationship_type": "uses",
                                        "toStix": {"x_mitre_id": ttp},
                                    }
                                }
                                for ttp in ttps
                            ]
                        },
                    }
                }
            ]
        }
    }


class TestEnrichCve:
    def test_returns_enrichment_with_ttps(self):
        client = _make_client()
        client.client.execute.return_value = _cve_response(
            "CVE-2024-1234", ["T1190", "T1021"], 9.8
        )

        result = client.enrich_cve("CVE-2024-1234")

        assert result is not None
        assert result["cve_id"] == "CVE-2024-1234"
        assert "T1190" in result["mitre_techniques"]
        assert "T1021" in result["mitre_techniques"]
        assert result["active_threat"] is True
        assert result["cvss_base"] == 9.8

    def test_returns_none_when_not_found(self):
        client = _make_client()
        client.client.execute.return_value = {"vulnerabilities": {"edges": []}}

        result = client.enrich_cve("CVE-9999-0001")

        assert result is None

    def test_active_threat_false_when_no_ttps(self):
        client = _make_client()
        client.client.execute.return_value = _cve_response(
            "CVE-2024-5678", [], 5.0
        )

        result = client.enrich_cve("CVE-2024-5678")

        assert result is not None
        assert result["active_threat"] is False
        assert result["mitre_techniques"] == []

    def test_raises_cti_error_on_network_failure(self):
        client = _make_client()
        client.client.execute.side_effect = Exception("Connection refused")

        with pytest.raises(CTIEnrichmentError, match="CVE-2024-1234"):
            client.enrich_cve("CVE-2024-1234")


class TestGetActiveCampaigns:
    def test_returns_campaign_count(self):
        client = _make_client()
        client.client.execute.return_value = {
            "attackPatterns": {
                "edges": [
                    {
                        "node": {
                            "x_mitre_id": "T1190",
                            "name": "Exploit Public-Facing Application",
                            "stixCoreRelationships": {
                                "edges": [
                                    {"node": {"fromStix": {"name": "APT29"}}},
                                    {"node": {"fromStix": {"name": "APT28"}}},
                                ]
                            },
                        }
                    }
                ]
            }
        }

        result = client.get_active_campaigns(["T1190"])

        assert result["active_campaigns"] == 2
        assert "T1190" in result["techniques"]

    def test_returns_zero_for_empty_ttp_list(self):
        client = _make_client()
        result = client.get_active_campaigns([])

        assert result["active_campaigns"] == 0
        client.client.execute.assert_not_called()

    def test_graceful_fallback_on_network_error(self):
        client = _make_client()
        client.client.execute.side_effect = Exception("timeout")

        result = client.get_active_campaigns(["T1190"])

        assert result["active_campaigns"] == 0
