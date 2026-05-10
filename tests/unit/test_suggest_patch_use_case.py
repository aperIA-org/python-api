from unittest.mock import MagicMock, call
from uuid import uuid4

import pytest

from application.remediation.suggest_patch_use_case import SuggestPatchUseCase
from domain.finding.entities import Finding
from domain.finding.value_objects import Severity

_SHA = "a" * 40


def _finding(
    file_path: str | None = "app/auth.py",
    line_number: int | None = 42,
    severity: Severity = Severity.HIGH,
) -> Finding:
    return Finding(
        source="semgrep",
        severity=severity,
        title="SQL Injection",
        description="Unsanitized input in query",
        file_path=file_path,
        line_number=line_number,
        commit_sha=_SHA,
        repo_url="https://github.com/org/repo",
    )


class TestSuggestPatchUseCase:
    def test_posts_suggestion_for_actionable_finding(self):
        github = MagicMock()
        finding = _finding()
        remediation = {
            "finding_id": str(finding.id),
            "finding_title": "SQL Injection",
            "explanation": "Use parameterized queries",
            "patch_diff": "cursor.execute(query, (user_id,))",
            "requires_secret_rotation": False,
            "rotation_instructions": "",
        }

        posted = SuggestPatchUseCase(github).execute(
            remediations=[remediation],
            findings=[finding],
            repo_full_name="org/repo",
            commit_sha=_SHA,
            pr_number=7,
        )

        assert posted == 1
        github.create_inline_suggestion.assert_called_once_with(
            repo_full_name="org/repo",
            pr_number=7,
            commit_sha=_SHA,
            file_path="app/auth.py",
            line=42,
            suggestion_code="cursor.execute(query, (user_id,))",
            context_message=pytest.approx(
                "**aperIA: HIGH — SQL Injection**\n\nUse parameterized queries",
                abs=False,
            ),
        )

    def test_skips_remediation_without_finding_id_match(self):
        github = MagicMock()
        finding = _finding()
        remediation = {
            "finding_id": str(uuid4()),  # ID que não existe no findings list
            "patch_diff": "some patch",
        }

        posted = SuggestPatchUseCase(github).execute(
            remediations=[remediation],
            findings=[finding],
            repo_full_name="org/repo",
            commit_sha=_SHA,
            pr_number=7,
        )

        assert posted == 0
        github.create_inline_suggestion.assert_not_called()

    def test_skips_finding_without_file_path(self):
        github = MagicMock()
        finding = _finding(file_path=None, line_number=None)
        remediation = {
            "finding_id": str(finding.id),
            "patch_diff": "some patch",
        }

        posted = SuggestPatchUseCase(github).execute(
            remediations=[remediation],
            findings=[finding],
            repo_full_name="org/repo",
            commit_sha=_SHA,
            pr_number=7,
        )

        assert posted == 0

    def test_skips_remediation_without_patch_diff(self):
        github = MagicMock()
        finding = _finding()
        remediation = {
            "finding_id": str(finding.id),
            "patch_diff": "",
        }

        posted = SuggestPatchUseCase(github).execute(
            remediations=[remediation],
            findings=[finding],
            repo_full_name="org/repo",
            commit_sha=_SHA,
            pr_number=7,
        )

        assert posted == 0

    def test_includes_rotation_warning_for_secrets(self):
        github = MagicMock()
        finding = _finding(severity=Severity.CRITICAL)
        remediation = {
            "finding_id": str(finding.id),
            "finding_title": "AWS Key Exposed",
            "explanation": "Key hardcoded in source",
            "patch_diff": 'key = os.environ.get("AWS_ACCESS_KEY_ID")',
            "requires_secret_rotation": True,
            "rotation_instructions": "Revoke at IAM console",
        }

        SuggestPatchUseCase(github).execute(
            remediations=[remediation],
            findings=[finding],
            repo_full_name="org/repo",
            commit_sha=_SHA,
            pr_number=3,
        )

        call_kwargs = github.create_inline_suggestion.call_args.kwargs
        assert "⚠️" in call_kwargs["context_message"]
        assert "Revoke at IAM console" in call_kwargs["context_message"]

    def test_continues_after_single_suggestion_failure(self):
        github = MagicMock()
        github.create_inline_suggestion.side_effect = [Exception("GitHub 422"), None]

        f1 = _finding(file_path="a.py", line_number=1)
        f2 = _finding(file_path="b.py", line_number=2)
        remediations = [
            {"finding_id": str(f1.id), "patch_diff": "patch1",
             "finding_title": "t", "explanation": "e",
             "requires_secret_rotation": False, "rotation_instructions": ""},
            {"finding_id": str(f2.id), "patch_diff": "patch2",
             "finding_title": "t", "explanation": "e",
             "requires_secret_rotation": False, "rotation_instructions": ""},
        ]

        posted = SuggestPatchUseCase(github).execute(
            remediations=remediations,
            findings=[f1, f2],
            repo_full_name="org/repo",
            commit_sha=_SHA,
            pr_number=1,
        )

        assert posted == 1
        assert github.create_inline_suggestion.call_count == 2
