"""Testes do OpenCTIClient — 3 cenários obrigatórios (Semana 8).

Nota técnica sobre mocks: ``RequestsHTTPTransport`` do ``gql`` usa
a biblioteca ``requests`` por baixo. ``respx`` (mencionado na
decisão #1) só mocka ``httpx``. Para ``requests`` o equivalente
canônico é ``requests-mock``, que oferece a mesma API
declarativa.

O spirit da decisão #1 — "mock no nível HTTP, sem servidor real,
3 cenários obrigatórios (CVE encontrado / CVE não encontrado / 503)" —
é preservado integralmente.
"""
from __future__ import annotations

import pytest
import requests_mock as rm_module

from app.infrastructure.intelligence.opencti_client import OpenCTIClient


# Fixture válida apenas em teste (token="test"), conforme decisão #1.
_TEST_URL = "http://opencti:8081"
_TEST_TOKEN = "test"
_GRAPHQL_ENDPOINT = f"{_TEST_URL}/graphql"


# Resposta mockada para CVE-2021-44228 com TTP T1190 (Exploit Public-Facing App)
_CVE_FOUND_RESPONSE = {
    "data": {
        "vulnerabilities": {
            "edges": [
                {
                    "node": {
                        "name": "CVE-2021-44228",
                        "x_opencti_cvss_base_score": 10.0,
                        "stixCoreRelationships": {
                            "edges": [
                                {
                                    "node": {
                                        "relationship_type": "targets",
                                        "toStix": {
                                            "name": "Exploit Public-Facing Application",
                                            "x_mitre_id": "T1190",
                                        },
                                    }
                                },
                                {
                                    "node": {
                                        "relationship_type": "targets",
                                        "toStix": {
                                            "name": "Command and Scripting Interpreter",
                                            "x_mitre_id": "T1059",
                                        },
                                    }
                                },
                            ]
                        },
                    }
                }
            ]
        }
    }
}

_CVE_NOT_FOUND_RESPONSE = {
    "data": {
        "vulnerabilities": {
            "edges": []
        }
    }
}


@pytest.fixture
def requests_mock_ctx():
    """Mocker do ``requests`` no estilo context manager."""
    with rm_module.Mocker() as m:
        yield m


# -----------------------------------------------------------------------------
# Cenário 1 — CVE encontrado
# -----------------------------------------------------------------------------


class TestCveFound:
    def test_returns_mitre_techniques_for_known_cve(self, requests_mock_ctx):
        requests_mock_ctx.post(_GRAPHQL_ENDPOINT, json=_CVE_FOUND_RESPONSE)
        client = OpenCTIClient(url=_TEST_URL, token=_TEST_TOKEN)

        result = client.enrich_cve("CVE-2021-44228")

        assert result is not None
        assert result["cve_id"] == "CVE-2021-44228"
        assert "T1190" in result["mitre_techniques"]
        assert result["active_threat"] is True
        assert result["cvss_base"] == 10.0

    def test_multiple_ttps_aggregated(self, requests_mock_ctx):
        requests_mock_ctx.post(_GRAPHQL_ENDPOINT, json=_CVE_FOUND_RESPONSE)
        client = OpenCTIClient(url=_TEST_URL, token=_TEST_TOKEN)

        result = client.enrich_cve("CVE-2021-44228")

        assert len(result["mitre_techniques"]) == 2
        assert sorted(result["mitre_techniques"]) == ["T1059", "T1190"]

    def test_bearer_token_in_request_header(self, requests_mock_ctx):
        requests_mock_ctx.post(_GRAPHQL_ENDPOINT, json=_CVE_FOUND_RESPONSE)
        client = OpenCTIClient(url=_TEST_URL, token="secret-prod-token")

        client.enrich_cve("CVE-2021-44228")

        last_request = requests_mock_ctx.last_request
        assert last_request.headers["Authorization"] == "Bearer secret-prod-token"


# -----------------------------------------------------------------------------
# Cenário 2 — CVE não encontrado
# -----------------------------------------------------------------------------


class TestCveNotFound:
    def test_returns_none_when_no_edges(self, requests_mock_ctx):
        requests_mock_ctx.post(_GRAPHQL_ENDPOINT, json=_CVE_NOT_FOUND_RESPONSE)
        client = OpenCTIClient(url=_TEST_URL, token=_TEST_TOKEN)

        result = client.enrich_cve("CVE-9999-99999")

        assert result is None

    def test_returns_none_when_missing_vulnerabilities_key(self, requests_mock_ctx):
        # Schema diferente / API rota errada — não deve quebrar.
        requests_mock_ctx.post(_GRAPHQL_ENDPOINT, json={"data": {}})
        client = OpenCTIClient(url=_TEST_URL, token=_TEST_TOKEN)

        assert client.enrich_cve("CVE-2024-0001") is None


# -----------------------------------------------------------------------------
# Cenário 3 — OpenCTI retornando 503
# -----------------------------------------------------------------------------


class TestOpenctiUnavailable:
    def test_503_returns_none_without_propagating(self, requests_mock_ctx):
        requests_mock_ctx.post(_GRAPHQL_ENDPOINT, status_code=503, text="Service Unavailable")
        client = OpenCTIClient(url=_TEST_URL, token=_TEST_TOKEN)

        # Não deve levantar — fault isolation total
        result = client.enrich_cve("CVE-2021-44228")
        assert result is None

    def test_500_returns_none(self, requests_mock_ctx):
        requests_mock_ctx.post(_GRAPHQL_ENDPOINT, status_code=500)
        client = OpenCTIClient(url=_TEST_URL, token=_TEST_TOKEN)
        assert client.enrich_cve("CVE-2021-44228") is None

    def test_connection_error_returns_none(self, requests_mock_ctx):
        from requests.exceptions import ConnectionError as ReqConnError

        requests_mock_ctx.post(_GRAPHQL_ENDPOINT, exc=ReqConnError("DNS fail"))
        client = OpenCTIClient(url=_TEST_URL, token=_TEST_TOKEN)
        assert client.enrich_cve("CVE-2021-44228") is None

    def test_invalid_json_returns_none(self, requests_mock_ctx):
        requests_mock_ctx.post(_GRAPHQL_ENDPOINT, text="<html>500</html>")
        client = OpenCTIClient(url=_TEST_URL, token=_TEST_TOKEN)
        assert client.enrich_cve("CVE-2021-44228") is None


# -----------------------------------------------------------------------------
# Constraint da decisão #3 — DEBT comment presente
# -----------------------------------------------------------------------------


class TestDebtCommentPresent:
    def test_enrich_cve_has_debt_comment(self):
        import inspect

        from app.infrastructure.intelligence import opencti_client

        source = inspect.getsource(opencti_client.OpenCTIClient.enrich_cve)
        assert "DEBT" in source
        assert "cache Redis" in source
        assert "TTL" in source
