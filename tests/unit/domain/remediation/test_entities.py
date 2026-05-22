from dataclasses import fields
from uuid import uuid4

from app.domain.remediation.entities import Remediation, RemediationStatus


def _make_remediation(**overrides) -> Remediation:
    base = {
        "finding_id": uuid4(),
        "scan_job_id": uuid4(),
        "patch_diff": "- bad\n+ good",
        "explanation": "fix",
    }
    base.update(overrides)
    return Remediation(**base)


class TestRemediationInvariants:
    def test_no_auto_applied_field(self):
        field_names = {f.name for f in fields(Remediation)}
        assert "auto_applied" not in field_names

    def test_default_status_is_suggested(self):
        r = _make_remediation()
        assert r.status is RemediationStatus.SUGGESTED

    def test_default_requires_rotation_false(self):
        r = _make_remediation()
        assert r.requires_secret_rotation is False

    def test_github_comment_id_optional(self):
        r = _make_remediation()
        assert r.github_comment_id is None

    def test_status_lifecycle_values(self):
        # Garante os 4 estados esperados
        assert RemediationStatus.SUGGESTED.value == "suggested"
        assert RemediationStatus.APPROVED.value == "approved"
        assert RemediationStatus.REJECTED.value == "rejected"
        assert RemediationStatus.MERGED.value == "merged"

    def test_can_be_approved(self):
        r = _make_remediation()
        r.status = RemediationStatus.APPROVED
        r.approved_by = "alice@example.com"
        assert r.status is RemediationStatus.APPROVED
        assert r.approved_by == "alice@example.com"
