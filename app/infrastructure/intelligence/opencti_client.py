"""Cliente OpenCTI síncrono para enriquecimento CTI no Tier 3.

Decisões operacionais aplicadas (Semana 8):

- **Síncrono** — workers Tier 3 rodam com ``concurrency=1`` e não se
  beneficiam de async. Usa ``RequestsHTTPTransport`` (decisão #2).
- **Fault isolation**: ``enrich_cve()`` NUNCA levanta. Qualquer erro
  (timeout, 5xx, GraphQL malformado, schema diferente) vira ``None``
  + log warning. O caller trata ``None`` como ``cti_data={}`` e o
  pipeline continua em modo degradado (decisão #2).
- **Sem cache LRU** no MVP (decisão #3). A solução correta é Redis
  com TTL — marcado como ``DEBT`` no método para revisão pós-MVP.
- **Token nunca hardcoded** — vem de ``settings.OPENCTI_TOKEN``.
"""
from __future__ import annotations

import structlog
from gql import Client, gql
from gql.transport.requests import RequestsHTTPTransport

from app.config import settings

logger = structlog.get_logger()


_ENRICH_QUERY = gql(
    """
    query GetVulnerability($cve: String!) {
      vulnerabilities(filters: {key: "name", values: [$cve]}) {
        edges {
          node {
            name
            x_opencti_cvss_base_score
            stixCoreRelationships {
              edges {
                node {
                  relationship_type
                  toStix {
                    ... on AttackPattern { name x_mitre_id }
                  }
                }
              }
            }
          }
        }
      }
    }
    """
)


class OpenCTIClient:
    """Cliente GraphQL para enriquecimento de findings com TTPs MITRE."""

    def __init__(
        self,
        url: str | None = None,
        token: str | None = None,
    ) -> None:
        resolved_url = url or settings.OPENCTI_URL
        resolved_token = token or settings.OPENCTI_TOKEN
        transport = RequestsHTTPTransport(
            url=f"{resolved_url}/graphql",
            headers={"Authorization": f"Bearer {resolved_token}"},
            timeout=30,
            retries=1,
        )
        self.client = Client(
            transport=transport,
            fetch_schema_from_transport=False,
        )

    def enrich_cve(self, cve_id: str) -> dict | None:
        # DEBT: cache Redis TTL=300s por cve_id pós-MVP (não LRU em memória —
        # não compartilha entre workers). Chave: opencti:cve:{cve_id}.
        try:
            result = self.client.execute(
                _ENRICH_QUERY, variable_values={"cve": cve_id}
            )
        except Exception as exc:  # noqa: BLE001 — fault isolation total
            logger.warning(
                "opencti_enrich_failed",
                cve_id=cve_id,
                error=str(exc),
                error_type=type(exc).__name__,
            )
            return None

        edges = (result or {}).get("vulnerabilities", {}).get("edges", []) or []
        if not edges:
            logger.info("opencti_cve_not_found", cve_id=cve_id)
            return None

        node = edges[0].get("node", {}) or {}
        mitre_techniques: list[str] = []
        for rel in (node.get("stixCoreRelationships", {}) or {}).get("edges", []) or []:
            to_stix = (rel.get("node", {}) or {}).get("toStix", {}) or {}
            mitre = to_stix.get("x_mitre_id")
            if mitre:
                mitre_techniques.append(mitre)

        return {
            "cve_id": cve_id,
            "mitre_techniques": mitre_techniques,
            "active_threat": len(mitre_techniques) > 0,
            "cvss_base": node.get("x_opencti_cvss_base_score"),
        }
