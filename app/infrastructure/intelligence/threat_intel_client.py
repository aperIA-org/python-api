"""Cliente de Threat Intelligence leve (CISA KEV + EPSS).

Substitui o OpenCTI no pipeline com a MESMA interface pública
(``enrich_cve(cve_id) -> dict | None``), mas SEM infra: o OpenCTI exigia
ElasticSearch/RabbitMQ/MinIO (vários GB, inviável na máquina). Aqui:

- **CISA KEV** — arquivo JSON com ~1656 CVEs comprovadamente explorados no
  mundo real. Responde "isto é ameaça ATIVA?" — o sinal mais honesto que existe.
- **EPSS** (FIRST.org) — API REST grátis, probabilidade (0-1) de exploração nos
  próximos 30 dias. Responde "qual a chance de exploração?".

Decisões de desenho (seguindo o padrão do ``opencti_client``):

- **Síncrono** (``httpx.Client``) — os workers Tier 3 são síncronos.
- **Fault isolation total** — nenhum método levanta. Qualquer erro (rede,
  timeout, 5xx, JSON inválido) vira ``logger.warning`` e "essa fonte não
  respondeu". Só retorna ``None`` quando AMBAS as fontes falham; o caller trata
  ``None`` como "sem enriquecimento", igual ao OpenCTI fazia.
- **Catálogo KEV cacheado em memória** (nível de módulo, com TTL). O catálogo
  inteiro é baixado UMA vez e vira um dict ``{cveID -> record}``; a checagem por
  CVE é O(1). Rebaixá-lo a cada ``enrich_cve`` seria 1656 CVEs por chamada.
"""
from __future__ import annotations

import time

import httpx
import structlog

from app.config import settings

logger = structlog.get_logger()


# --- Cache do catálogo KEV (nível de módulo, por worker) ---------------------
# Um dict {cveID -> record} + o instante monotônico em que foi baixado, para o
# TTL. Sem lock: workers são processos separados e, dentro de um, o pior caso é
# baixar duas vezes — inofensivo. `time.monotonic()` (não wall-clock) porque só
# medimos duração de TTL, imune a ajustes do relógio.
_kev_cache: dict[str, dict] | None = None
_kev_cached_at: float = 0.0


def _reset_kev_cache() -> None:
    """Zera o cache de módulo. Existe para os testes: como o cache é global,
    um teste vazaria o catálogo para o próximo. Chamado por um fixture autouse.
    """
    global _kev_cache, _kev_cached_at
    _kev_cache = None
    _kev_cached_at = 0.0


class ThreatIntelClient:
    """Enriquece um CVE com KEV (ameaça ativa) + EPSS (probabilidade)."""

    def _load_kev_catalog(self) -> dict[str, dict] | None:
        """Retorna o catálogo KEV como ``{cveID -> record}``, cacheado com TTL.

        Baixa o catálogo inteiro só quando o cache está vazio ou expirou. Em
        caso de falha retorna ``None`` (KEV indisponível) SEM tocar no cache —
        um catálogo válido anterior continua servindo até o TTL natural.
        """
        global _kev_cache, _kev_cached_at

        agora = time.monotonic()
        if _kev_cache is not None and (agora - _kev_cached_at) < settings.CTI_CACHE_TTL_SECONDS:
            return _kev_cache

        try:
            resp = httpx.get(settings.CISA_KEV_URL, timeout=settings.CTI_HTTP_TIMEOUT)
            resp.raise_for_status()
            payload = resp.json()
            vulns = payload.get("vulnerabilities", []) or []
            catalogo = {
                v["cveID"]: v
                for v in vulns
                if isinstance(v, dict) and v.get("cveID")
            }
        except Exception as exc:  # noqa: BLE001 — fault isolation total
            logger.warning(
                "kev_catalog_fetch_failed",
                error=str(exc),
                error_type=type(exc).__name__,
            )
            return None

        _kev_cache = catalogo
        _kev_cached_at = agora
        return catalogo

    def _fetch_epss(self, cve_id: str) -> tuple[float, float] | None:
        """Consulta o EPSS de um CVE. Retorna ``(score, percentile)`` como
        floats, ou ``None`` se o EPSS falhou OU não conhece o CVE.

        Um CVE inexistente simplesmente não aparece em ``data`` — não é erro,
        só ausência de sinal. Os campos vêm como STRING e são convertidos.
        """
        try:
            resp = httpx.get(
                settings.EPSS_API_URL,
                params={"cve": cve_id},
                timeout=settings.CTI_HTTP_TIMEOUT,
            )
            resp.raise_for_status()
            data = resp.json().get("data", []) or []
        except Exception as exc:  # noqa: BLE001 — fault isolation total
            logger.warning(
                "epss_fetch_failed",
                cve_id=cve_id,
                error=str(exc),
                error_type=type(exc).__name__,
            )
            return None

        for row in data:
            if isinstance(row, dict) and row.get("cve") == cve_id:
                try:
                    return float(row["epss"]), float(row["percentile"])
                except (KeyError, TypeError, ValueError) as exc:
                    logger.warning(
                        "epss_parse_failed",
                        cve_id=cve_id,
                        error=str(exc),
                    )
                    return None
        # CVE não está no EPSS: ausência de sinal, não falha.
        return None

    def enrich_cve(self, cve_id: str) -> dict | None:
        """Enriquece ``cve_id`` com KEV + EPSS.

        Retorna ``None`` SOMENTE se ambas as fontes falharem (rede fora). Se ao
        menos uma respondeu, devolve o dict de enriquecimento — mesmo que a
        outra fonte esteja fora ou não conheça o CVE.
        """
        catalogo = self._load_kev_catalog()
        epss = self._fetch_epss(cve_id)

        if catalogo is None and epss is None:
            # Ambas as fontes falharam (distinto de "responderam e não têm o
            # CVE"). Sem enriquecimento — o caller degrada como no OpenCTI.
            logger.warning("threat_intel_all_sources_failed", cve_id=cve_id)
            return None

        kev_record = (catalogo or {}).get(cve_id)
        known_exploited = kev_record is not None
        ransomware_campaign = bool(
            kev_record and kev_record.get("knownRansomwareCampaignUse") == "Known"
        )

        epss_score = epss[0] if epss is not None else None
        epss_percentile = epss[1] if epss is not None else None

        active_threat = known_exploited or (
            epss_score is not None and epss_score >= settings.EPSS_ACTIVE_THRESHOLD
        )

        return {
            "cve_id": cve_id,
            "known_exploited": known_exploited,
            "ransomware_campaign": ransomware_campaign,
            "epss_score": epss_score,
            "epss_percentile": epss_percentile,
            # Derivados / compat com o merge e o RiskScorer existentes:
            "active_threat": active_threat,
            # `active_campaigns` corrige um bug de nome de campo no RiskScorer.
            "active_campaigns": ransomware_campaign,
            # KEV/EPSS não fornecem TTPs; OTX é o passo 2. MANTER a chave vazia.
            "mitre_techniques": [],
            # Não fornecido por estas fontes; mantido None por compat.
            "cvss_base": None,
        }
