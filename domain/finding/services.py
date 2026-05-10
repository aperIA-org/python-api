from domain.finding.entities import Finding, RiskScore


class FindingDeduplicator:
    """Remove findings duplicados antes de persistir."""

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
    Score = CVSS(25%) + CTI_active(25%) + Caldera_success(30%) + Business_impact(20%)
    Secret verificado eleva score mínimo a 90.
    """

    _SEVERITY_CVSS: dict[str, float] = {
        "critical": 100.0,
        "high":     75.0,
        "medium":   50.0,
        "low":      25.0,
        "info":     0.0,
    }

    def calculate(
        self,
        findings: list[Finding],
        cti_data: dict,
        caldera_results: dict,
    ) -> RiskScore:
        cvss = self._cvss_component(findings)
        cti = self._cti_component(cti_data)
        caldera = self._caldera_component(caldera_results)
        business = self._business_component(findings)

        raw = cvss * 0.25 + cti * 0.25 + caldera * 0.30 + business * 0.20
        has_verified_secret = any(f.is_critical_secret() for f in findings)
        final = max(int(raw), 90) if has_verified_secret else int(raw)

        return RiskScore(
            value=min(final, 100),
            cvss_component=cvss,
            cti_component=cti,
            caldera_component=caldera,
            business_component=business,
        )

    def _cvss_component(self, findings: list[Finding]) -> float:
        if not findings:
            return 0.0
        scores = [self._SEVERITY_CVSS.get(f.severity.value, 0.0) for f in findings]
        return max(scores)

    def _cti_component(self, cti_data: dict) -> float:
        if not cti_data:
            return 0.0
        active_campaigns = cti_data.get("active_campaigns", 0)
        return min(active_campaigns * 25.0, 100.0)

    def _caldera_component(self, caldera_results: dict) -> float:
        if not caldera_results:
            return 0.0
        success_rate = caldera_results.get("success_rate", 0.0)
        return float(success_rate) * 100.0

    def _business_component(self, findings: list[Finding]) -> float:
        critical_count = sum(1 for f in findings if f.severity.value == "critical")
        high_count = sum(1 for f in findings if f.severity.value == "high")
        return min((critical_count * 30.0) + (high_count * 15.0), 100.0)


class AttackPathBuilder:
    """Constrói a sequência de eventos que forma um attack path."""

    def build_narrative(self, findings: list[Finding], ttp_data: dict) -> str:
        # DEBT: lógica de correlação será aprimorada pelo Claude na Fase 3
        sources = sorted({f.source for f in findings})
        severities = sorted({f.severity.value for f in findings}, reverse=True)
        ttps = list(ttp_data.get("techniques", []))
        return (
            f"Attack path identified across {len(findings)} findings "
            f"from sources: {', '.join(sources)}. "
            f"Severity range: {severities[0] if severities else 'unknown'}. "
            f"MITRE ATT&CK techniques: {', '.join(ttps[:5]) if ttps else 'none mapped'}."
        )
