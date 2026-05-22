import pytest

from app.domain.finding.value_objects import (
    Severity,
    CVEId,
    CommitSha,
    BusinessImpact,
)


class TestSeverityFromCvss:
    def test_critical_at_9_0(self):
        assert Severity.from_cvss(9.0) is Severity.CRITICAL

    def test_critical_at_10_0(self):
        assert Severity.from_cvss(10.0) is Severity.CRITICAL

    def test_high_at_7_0(self):
        assert Severity.from_cvss(7.0) is Severity.HIGH

    def test_high_at_8_9(self):
        assert Severity.from_cvss(8.9) is Severity.HIGH

    def test_medium_at_4_0(self):
        assert Severity.from_cvss(4.0) is Severity.MEDIUM

    def test_medium_at_6_9(self):
        assert Severity.from_cvss(6.9) is Severity.MEDIUM

    def test_low_above_zero(self):
        assert Severity.from_cvss(0.1) is Severity.LOW

    def test_low_at_3_9(self):
        assert Severity.from_cvss(3.9) is Severity.LOW

    def test_info_at_zero(self):
        assert Severity.from_cvss(0.0) is Severity.INFO

    def test_info_for_negative(self):
        assert Severity.from_cvss(-1.0) is Severity.INFO


class TestSeverityStrSemantics:
    def test_compares_equal_to_string(self):
        assert Severity.CRITICAL == "critical"

    def test_str_value(self):
        assert Severity.HIGH.value == "high"


class TestCVEId:
    def test_valid_cve_id(self):
        cve = CVEId("CVE-2021-44228")
        assert str(cve) == "CVE-2021-44228"

    def test_valid_cve_id_with_more_digits(self):
        cve = CVEId("CVE-2024-1234567")
        assert str(cve) == "CVE-2024-1234567"

    def test_invalid_format_raises(self):
        with pytest.raises(ValueError, match="CVE ID inválido"):
            CVEId("CVE-abc-xyz")

    def test_empty_raises(self):
        with pytest.raises(ValueError):
            CVEId("")

    def test_random_string_raises(self):
        with pytest.raises(ValueError):
            CVEId("not-a-cve")

    def test_is_frozen(self):
        cve = CVEId("CVE-2021-44228")
        with pytest.raises(Exception):
            cve.value = "CVE-2024-0001"  # type: ignore[misc]


class TestCommitSha:
    def test_valid_40_hex(self):
        sha = CommitSha("a" * 40)
        assert str(sha) == "a" * 40

    def test_real_looking_sha(self):
        sha = CommitSha("0123456789abcdef0123456789abcdef01234567")
        assert str(sha) == "0123456789abcdef0123456789abcdef01234567"

    def test_too_short_raises(self):
        with pytest.raises(ValueError, match="Commit SHA inválido"):
            CommitSha("abc")

    def test_too_long_raises(self):
        with pytest.raises(ValueError):
            CommitSha("a" * 41)

    def test_non_hex_raises(self):
        with pytest.raises(ValueError):
            CommitSha("g" * 40)

    def test_uppercase_raises(self):
        with pytest.raises(ValueError):
            CommitSha("A" * 40)


class TestBusinessImpact:
    def test_only_description(self):
        impact = BusinessImpact(description="Vazamento de dados")
        assert impact.description == "Vazamento de dados"
        assert impact.estimated_cost_brl is None
        assert impact.compliance_violations == []

    def test_full(self):
        impact = BusinessImpact(
            description="LGPD breach",
            estimated_cost_brl=500_000.0,
            compliance_violations=["LGPD", "PCI"],
        )
        assert impact.estimated_cost_brl == 500_000.0
        assert "LGPD" in impact.compliance_violations

    def test_is_frozen(self):
        impact = BusinessImpact(description="x")
        with pytest.raises(Exception):
            impact.description = "y"  # type: ignore[misc]
