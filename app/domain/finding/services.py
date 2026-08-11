from app.domain.finding.entities import Finding
from app.domain.finding.value_objects import Severity


class FindingDeduplicator:
    def deduplicate(self, findings: list[Finding]) -> list[Finding]:
        seen: set[str] = set()
        unique: list[Finding] = []
        for f in findings:
            key = f.dedup_key()
            if key not in seen:
                seen.add(key)
                unique.append(f)
        return unique


class RiskScorer:
    """
    Score 0-100:
      CVSS       25% — severidade dos findings
      CTI        25% — campanhas ativas no OpenCTI para esses CVEs
      Caldera    30% — taxa de sucesso da emulação no sandbox
      Business   20% — criticidade dos assets afetados

    Regra hard: secret_verified=True → score mínimo 90.
    """

    def calculate(
        self,
        findings: list[Finding],
        cti_data: dict,
        caldera_results: dict,
    ) -> int:
        cvss_score = self._cvss_component(findings)
        cti_score = self._cti_component(cti_data)
        caldera_score = self._caldera_component(caldera_results)
        business_score = self._business_component(findings)

        total = int(
            cvss_score * 0.25
            + cti_score * 0.25
            + caldera_score * 0.30
            + business_score * 0.20
        )
        has_verified_secret = any(f.is_critical_secret() for f in findings)
        return max(total, 90) if has_verified_secret else total

    def _cvss_component(self, findings: list[Finding]) -> float:
        if not findings:
            return 0.0
        severity_map = {
            Severity.CRITICAL: 100.0,
            Severity.HIGH: 75.0,
            Severity.MEDIUM: 50.0,
            Severity.LOW: 25.0,
            Severity.INFO: 0.0,
        }
        return max(severity_map[f.severity] for f in findings)

    def _cti_component(self, cti_data: dict) -> float:
        """Componente CTI do score, agora alimentado por KEV + EPSS.

        Antes: ``100 if cti_data.get("active_campaigns") else 25`` — mas o cliente
        OpenCTI nunca setava ``active_campaigns`` (setava ``active_threat``), então
        este componente **sempre valia 25**, com ou sem OpenCTI de pé. Bug latente,
        corrigido de vez aqui.

        Agora: exploração comprovada (KEV) ou campanha de ransomware ativa → 100
        (é o teto de ameaça real). Sem isso, gradua pelo EPSS (probabilidade de
        exploração). Sem sinal nenhum → o piso de 25 de antes.
        """
        if cti_data.get("known_exploited") or cti_data.get("active_campaigns"):
            return 100.0
        epss = cti_data.get("epss_score")
        if isinstance(epss, (int, float)):
            return 25.0 + 75.0 * max(0.0, min(1.0, float(epss)))
        return 25.0

    def _caldera_component(self, caldera_results: dict) -> float:
        return caldera_results.get("success_rate", 0.0) * 100.0

    def _business_component(self, findings: list[Finding]) -> float:
        return (
            100.0
            if any(f.asset_criticality == "critical" for f in findings)
            else 40.0
        )
