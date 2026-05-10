import structlog
from gql import gql, Client
from gql.transport.requests import RequestsHTTPTransport

from core.config import settings
from core.exceptions import CTIEnrichmentError

logger = structlog.get_logger()

_CVE_QUERY = gql("""
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
""")

_CAMPAIGNS_QUERY = gql("""
query GetCampaigns($ttps: [String!]!) {
  attackPatterns(filters: {key: "x_mitre_id", values: $ttps}) {
    edges {
      node {
        x_mitre_id
        name
        stixCoreRelationships(relationship_type: "uses") {
          edges {
            node {
              fromStix {
                ... on Campaign { name first_seen last_seen }
                ... on ThreatActor { name sophistication }
              }
            }
          }
        }
      }
    }
  }
}
""")


class OpenCTIClient:
    def __init__(self) -> None:
        transport = RequestsHTTPTransport(
            url=f"{settings.OPENCTI_URL}/graphql",
            headers={"Authorization": f"Bearer {settings.OPENCTI_TOKEN}"},
            timeout=30,
        )
        self.client = Client(transport=transport, fetch_schema_from_transport=False)

    def enrich_cve(self, cve_id: str) -> dict | None:
        """Retorna TTPs MITRE e indicador de ameaça ativa para um CVE. None se não encontrado."""
        log = logger.bind(cve_id=cve_id)
        try:
            result = self.client.execute(_CVE_QUERY, variable_values={"cve": cve_id})
        except Exception as exc:
            log.warning("opencti_cve_query_failed", error=str(exc))
            raise CTIEnrichmentError(f"Falha ao enriquecer {cve_id}: {exc}") from exc

        edges = result.get("vulnerabilities", {}).get("edges", [])
        if not edges:
            log.info("opencti_cve_not_found")
            return None

        node = edges[0]["node"]
        mitre_techniques = [
            rel["node"]["toStix"]["x_mitre_id"]
            for rel in node.get("stixCoreRelationships", {}).get("edges", [])
            if rel["node"].get("toStix", {}).get("x_mitre_id")
        ]
        enrichment = {
            "cve_id": cve_id,
            "mitre_techniques": mitre_techniques,
            "active_threat": len(mitre_techniques) > 0,
            "cvss_base": node.get("x_opencti_cvss_base_score"),
        }
        log.info("opencti_cve_enriched", techniques=mitre_techniques)
        return enrichment

    def get_active_campaigns(self, ttp_ids: list[str]) -> dict:
        """Retorna campanhas e atores ativos mapeados para os TTPs fornecidos."""
        if not ttp_ids:
            return {"active_campaigns": 0, "techniques": []}

        log = logger.bind(ttp_count=len(ttp_ids))
        try:
            result = self.client.execute(
                _CAMPAIGNS_QUERY, variable_values={"ttps": ttp_ids}
            )
        except Exception as exc:
            log.warning("opencti_campaigns_query_failed", error=str(exc))
            return {"active_campaigns": 0, "techniques": ttp_ids}

        patterns = result.get("attackPatterns", {}).get("edges", [])
        active_count = 0
        for pattern in patterns:
            rels = (
                pattern["node"]
                .get("stixCoreRelationships", {})
                .get("edges", [])
            )
            active_count += len(rels)

        log.info("opencti_campaigns_done", active_campaigns=active_count)
        return {"active_campaigns": active_count, "techniques": ttp_ids}
