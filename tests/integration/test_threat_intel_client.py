"""Testes do ThreatIntelClient (CISA KEV + EPSS).

Cobertura obrigatória:

- CVE no KEV com ransomware "Known" → known_exploited/ransomware/active_*.
- CVE fora do KEV com EPSS alto → active_threat por EPSS.
- CVE fora do KEV com EPSS baixo → active_threat=False.
- CVE sem EPSS (ausente em `data`) → epss_score=None, sem quebrar.
- Conversão string → float dos campos EPSS.
- Cache do KEV: duas chamadas baixam o catálogo UMA vez só.
- KEV falha mas EPSS responde → ainda retorna dict (não None).
- Ambas falham → None.
- `mitre_techniques` sempre presente e vazio.

O cache do KEV é nível de módulo, então um fixture autouse o zera antes de cada
teste — sem isso, o catálogo de um teste vazaria para o próximo.
"""
from __future__ import annotations

import httpx
import pytest
import respx

from app.config import settings
from app.infrastructure.intelligence import threat_intel_client
from app.infrastructure.intelligence.threat_intel_client import ThreatIntelClient


_KEV_URL = settings.CISA_KEV_URL
_EPSS_URL = settings.EPSS_API_URL


@pytest.fixture(autouse=True)
def _limpa_cache_kev():
    """Zera o cache de módulo do KEV antes de cada teste (é global)."""
    threat_intel_client._reset_kev_cache()
    yield
    threat_intel_client._reset_kev_cache()


def _kev_payload(*records: dict) -> dict:
    return {
        "title": "CISA KEV",
        "catalogVersion": "2026.08.02",
        "count": len(records),
        "vulnerabilities": list(records),
    }


def _kev_record(cve_id: str, ransomware: str = "Unknown") -> dict:
    return {
        "cveID": cve_id,
        "vendorProject": "Acme",
        "product": "Widget",
        "vulnerabilityName": f"{cve_id} RCE",
        "dateAdded": "2021-12-10",
        "knownRansomwareCampaignUse": ransomware,
        "cwes": ["CWE-502"],
    }


def _epss_payload(*rows: dict) -> dict:
    return {"status": "OK", "data": list(rows)}


def _epss_row(cve_id: str, epss: str, percentile: str = "0.999990000") -> dict:
    return {"cve": cve_id, "epss": epss, "percentile": percentile, "date": "2026-08-02"}


def _mock_kev(payload: dict) -> respx.Route:
    return respx.get(_KEV_URL).mock(return_value=httpx.Response(200, json=payload))


def _mock_epss(payload: dict) -> respx.Route:
    return respx.get(_EPSS_URL).mock(return_value=httpx.Response(200, json=payload))


# -----------------------------------------------------------------------------
# KEV — ameaça ativa e ransomware
# -----------------------------------------------------------------------------


class TestKev:
    @respx.mock
    def test_cve_no_kev_com_ransomware_known(self):
        _mock_kev(_kev_payload(_kev_record("CVE-2021-44228", ransomware="Known")))
        _mock_epss(_epss_payload(_epss_row("CVE-2021-44228", "0.999990000")))

        result = ThreatIntelClient().enrich_cve("CVE-2021-44228")

        assert result is not None
        assert result["known_exploited"] is True
        assert result["ransomware_campaign"] is True
        assert result["active_campaigns"] is True
        assert result["active_threat"] is True

    @respx.mock
    def test_cve_no_kev_sem_ransomware(self):
        _mock_kev(_kev_payload(_kev_record("CVE-2021-44228", ransomware="Unknown")))
        _mock_epss(_epss_payload())  # EPSS não conhece

        result = ThreatIntelClient().enrich_cve("CVE-2021-44228")

        assert result["known_exploited"] is True
        assert result["ransomware_campaign"] is False
        assert result["active_campaigns"] is False
        # No KEV → ameaça ativa mesmo sem EPSS.
        assert result["active_threat"] is True


# -----------------------------------------------------------------------------
# EPSS — probabilidade fora do KEV
# -----------------------------------------------------------------------------


class TestEpss:
    @respx.mock
    def test_fora_do_kev_com_epss_alto_e_ativo(self):
        _mock_kev(_kev_payload())  # catálogo vazio, CVE não está lá
        _mock_epss(_epss_payload(_epss_row("CVE-2024-0001", "0.8500", "0.9700")))

        result = ThreatIntelClient().enrich_cve("CVE-2024-0001")

        assert result["known_exploited"] is False
        assert result["active_threat"] is True  # por EPSS >= threshold
        assert result["epss_score"] == pytest.approx(0.85)
        assert result["epss_percentile"] == pytest.approx(0.97)

    @respx.mock
    def test_fora_do_kev_com_epss_baixo_nao_ativo(self):
        _mock_kev(_kev_payload())
        _mock_epss(_epss_payload(_epss_row("CVE-2024-0002", "0.0100", "0.1200")))

        result = ThreatIntelClient().enrich_cve("CVE-2024-0002")

        assert result["known_exploited"] is False
        assert result["active_threat"] is False
        assert result["epss_score"] == pytest.approx(0.01)

    @respx.mock
    def test_epss_no_limite_exato_e_ativo(self):
        """`>=` threshold: exatamente 0.5 conta como ativo."""
        _mock_kev(_kev_payload())
        _mock_epss(_epss_payload(_epss_row("CVE-2024-0003", "0.5000")))

        result = ThreatIntelClient().enrich_cve("CVE-2024-0003")
        assert settings.EPSS_ACTIVE_THRESHOLD == 0.5
        assert result["active_threat"] is True

    @respx.mock
    def test_cve_sem_epss_nao_quebra(self):
        _mock_kev(_kev_payload())
        _mock_epss(_epss_payload())  # data vazia: CVE não aparece

        result = ThreatIntelClient().enrich_cve("CVE-2024-9999")

        assert result is not None
        assert result["epss_score"] is None
        assert result["epss_percentile"] is None
        assert result["known_exploited"] is False
        assert result["active_threat"] is False

    @respx.mock
    def test_epss_string_vira_float(self):
        _mock_kev(_kev_payload())
        _mock_epss(_epss_payload(_epss_row("CVE-2024-0004", "0.123450000", "0.678900000")))

        result = ThreatIntelClient().enrich_cve("CVE-2024-0004")

        assert isinstance(result["epss_score"], float)
        assert isinstance(result["epss_percentile"], float)
        assert result["epss_score"] == pytest.approx(0.12345)
        assert result["epss_percentile"] == pytest.approx(0.6789)


# -----------------------------------------------------------------------------
# Cache do catálogo KEV
# -----------------------------------------------------------------------------


class TestCacheKev:
    @respx.mock
    def test_catalogo_baixado_uma_vez_para_duas_chamadas(self):
        rota_kev = _mock_kev(_kev_payload(_kev_record("CVE-2021-44228")))
        _mock_epss(_epss_payload(_epss_row("CVE-2021-44228", "0.9000")))

        client = ThreatIntelClient()
        client.enrich_cve("CVE-2021-44228")
        client.enrich_cve("CVE-2021-44228")

        # KEV só uma vez (cacheado); EPSS uma por CVE (não cacheado).
        assert rota_kev.call_count == 1


# -----------------------------------------------------------------------------
# Fault isolation
# -----------------------------------------------------------------------------


class TestFaultIsolation:
    @respx.mock
    def test_kev_500_mas_epss_responde_retorna_dict(self):
        respx.get(_KEV_URL).mock(return_value=httpx.Response(500))
        _mock_epss(_epss_payload(_epss_row("CVE-2024-0005", "0.7000")))

        result = ThreatIntelClient().enrich_cve("CVE-2024-0005")

        assert result is not None  # uma fonte respondeu
        assert result["known_exploited"] is False  # KEV indisponível
        assert result["active_threat"] is True  # por EPSS
        assert result["epss_score"] == pytest.approx(0.7)

    @respx.mock
    def test_kev_timeout_mas_epss_responde(self):
        respx.get(_KEV_URL).mock(side_effect=httpx.ConnectTimeout("timeout"))
        _mock_epss(_epss_payload(_epss_row("CVE-2024-0006", "0.6000")))

        result = ThreatIntelClient().enrich_cve("CVE-2024-0006")

        assert result is not None
        assert result["active_threat"] is True

    @respx.mock
    def test_epss_falha_mas_kev_responde(self):
        _mock_kev(_kev_payload(_kev_record("CVE-2021-44228", ransomware="Known")))
        respx.get(_EPSS_URL).mock(return_value=httpx.Response(500))

        result = ThreatIntelClient().enrich_cve("CVE-2021-44228")

        assert result is not None
        assert result["known_exploited"] is True
        assert result["ransomware_campaign"] is True
        assert result["epss_score"] is None

    @respx.mock
    def test_ambas_falham_retorna_none(self):
        respx.get(_KEV_URL).mock(return_value=httpx.Response(500))
        respx.get(_EPSS_URL).mock(side_effect=httpx.ConnectError("down"))

        result = ThreatIntelClient().enrich_cve("CVE-2021-44228")

        assert result is None

    @respx.mock
    def test_kev_json_invalido_tratado_como_falha(self):
        respx.get(_KEV_URL).mock(return_value=httpx.Response(200, text="não é json"))
        respx.get(_EPSS_URL).mock(side_effect=httpx.ConnectError("down"))

        # KEV inválido + EPSS fora → ambas falharam → None.
        assert ThreatIntelClient().enrich_cve("CVE-2021-44228") is None


# -----------------------------------------------------------------------------
# Contrato de retorno
# -----------------------------------------------------------------------------


class TestContrato:
    @respx.mock
    def test_mitre_techniques_sempre_presente_e_vazio(self):
        _mock_kev(_kev_payload(_kev_record("CVE-2021-44228")))
        _mock_epss(_epss_payload(_epss_row("CVE-2021-44228", "0.9000")))

        result = ThreatIntelClient().enrich_cve("CVE-2021-44228")

        assert "mitre_techniques" in result
        assert result["mitre_techniques"] == []

    @respx.mock
    def test_cvss_base_none_e_cve_id_ecoado(self):
        _mock_kev(_kev_payload())
        _mock_epss(_epss_payload(_epss_row("CVE-2024-0007", "0.9000")))

        result = ThreatIntelClient().enrich_cve("CVE-2024-0007")

        assert result["cvss_base"] is None
        assert result["cve_id"] == "CVE-2024-0007"
