import structlog
import httpx

from core.config import settings
from core.exceptions import CTIEnrichmentError

logger = structlog.get_logger()

# TODO: validar com doc oficial — OpenCTI GraphQL API 6.x


class OpenCTIClient:
    def __init__(self) -> None:
        self._client = httpx.AsyncClient(
            base_url=settings.OPENCTI_URL,
            headers={"Authorization": f"Bearer {settings.OPENCTI_TOKEN}"},
            timeout=httpx.Timeout(30.0, connect=5.0),
        )

    async def enrich_cve(self, cve_id: str) -> dict:
        # DEBT: implementar query GraphQL real na Fase 2
        logger.bind(cve_id=cve_id).info("opencti_enrichment_started")
        return {}

    async def get_active_campaigns(self, ttp_ids: list[str]) -> dict:
        logger.bind(ttps=ttp_ids).info("opencti_campaigns_query")
        return {"active_campaigns": 0, "techniques": ttp_ids}
