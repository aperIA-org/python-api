import structlog

from domain.finding.entities import Finding
from infrastructure.git.github_client import GitHubClient

logger = structlog.get_logger()


class SuggestPatchUseCase:
    """
    Entrega patches como GitHub code suggestions inline — NUNCA auto-apply.
    O merge permanece bloqueado até o desenvolvedor aprovar a suggestion.
    """

    def __init__(self, github: GitHubClient) -> None:
        self.github = github

    def execute(
        self,
        remediations: list[dict],
        findings: list[Finding],
        repo_full_name: str,
        commit_sha: str,
        pr_number: int,
    ) -> int:
        """
        Posta code suggestion para cada remediação com file_path e line_number.
        Cross-referencia findings pelo finding_id para obter localização.
        Retorna número de suggestions postadas.
        """
        finding_map = {str(f.id): f for f in findings}
        posted = 0

        for rem in remediations:
            finding = finding_map.get(str(rem.get("finding_id", "")))
            if not finding or not finding.file_path or not finding.line_number:
                continue
            if not rem.get("patch_diff"):
                continue

            severity = finding.severity.value.upper()
            context_msg = (
                f"**aperIA: {severity} — {rem.get('finding_title', '')}**\n\n"
                f"{rem.get('explanation', '')}"
            )
            if rem.get("requires_secret_rotation"):
                context_msg += (
                    "\n\n⚠️ **Ação imediata:** revogar a credencial exposta "
                    "no serviço correspondente antes de fazer merge.\n\n"
                    f"{rem.get('rotation_instructions', '')}"
                )

            try:
                self.github.create_inline_suggestion(
                    repo_full_name=repo_full_name,
                    pr_number=pr_number,
                    commit_sha=commit_sha,
                    file_path=finding.file_path,
                    line=finding.line_number,
                    suggestion_code=rem["patch_diff"],
                    context_message=context_msg,
                )
                posted += 1
                logger.info(
                    "suggestion_posted",
                    finding_id=str(finding.id),
                    file_path=finding.file_path,
                    line=finding.line_number,
                )
            except Exception as exc:
                logger.warning(
                    "suggestion_post_failed",
                    finding_id=str(finding.id),
                    file_path=finding.file_path,
                    error=str(exc),
                )

        return posted
