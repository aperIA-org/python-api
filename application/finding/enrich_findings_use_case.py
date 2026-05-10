import structlog

from core.exceptions import CTIEnrichmentError
from domain.finding.entities import Finding
from infrastructure.intelligence.opencti_client import OpenCTIClient

logger = structlog.get_logger()


class EnrichFindingsUseCase:
    """
    Enriquece findings com CTI do OpenCTI: TTPs MITRE e campanhas ativas.
    Retorna dict com per_cve (por CVE) e active_campaigns (count para RiskScorer).
    """

    def __init__(self, opencti: OpenCTIClient | None = None) -> None:
        self.opencti = opencti or OpenCTIClient()

    def execute(self, findings: list[Finding], commit_sha: str) -> dict:
        log = logger.bind(commit_sha=commit_sha, findings_count=len(findings))
        log.info("enrichment_started")

        cve_ids = {
            str(f.cve_id)
            for f in findings
            if f.cve_id is not None
        }

        per_cve: dict[str, dict] = {}
        for cve_id in cve_ids:
            try:
                result = self.opencti.enrich_cve(cve_id)
                if result:
                    per_cve[cve_id] = result
            except CTIEnrichmentError as exc:
                log.warning("enrichment_cve_failed", cve_id=cve_id, error=str(exc))

        all_ttps = list({
            ttp
            for data in per_cve.values()
            for ttp in data.get("mitre_techniques", [])
        })

        try:
            campaigns = self.opencti.get_active_campaigns(all_ttps)
        except Exception as exc:
            log.warning("enrichment_campaigns_failed", error=str(exc))
            campaigns = {"active_campaigns": 0, "techniques": all_ttps}

        cti_data = {
            "per_cve": per_cve,
            "active_campaigns": campaigns.get("active_campaigns", 0),
            "techniques": all_ttps,
        }
        log.info(
            "enrichment_done",
            cves_enriched=len(per_cve),
            active_campaigns=cti_data["active_campaigns"],
        )
        return cti_data
