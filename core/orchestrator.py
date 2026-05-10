import subprocess
import tempfile
import os
from concurrent.futures import ThreadPoolExecutor, as_completed

import structlog

from core.config import settings
from core.exceptions import ScannerError
from domain.finding.entities import Finding
from domain.finding.services import FindingDeduplicator
from infrastructure.scanners.trufflehog_scanner import TruffleHogScanner
from infrastructure.scanners.semgrep_scanner import SemgrepScanner
from infrastructure.scanners.trivy_scanner import TrivyScanner
from infrastructure.scanners.zap_scanner import ZAPScanner
from infrastructure.scanners.openvas_scanner import OpenVASScanner
from infrastructure.scanners.wazuh_scanner import WazuhScanner
from infrastructure.scanners.prowler_scanner import ProwlerScanner
from infrastructure.git.github_client import GitHubClient, get_installation_token

logger = structlog.get_logger()

_deduplicator = FindingDeduplicator()


def run_pipeline(
    commit_sha: str,
    repo_url: str,
    pr_number: int | None = None,
    installation_id: int | None = None,
    base_sha: str | None = None,
    repo_full_name: str | None = None,
) -> list[Finding]:
    log = logger.bind(
        commit_sha=commit_sha,
        repo_url=repo_url,
        pr_number=pr_number,
    )
    log.info("pipeline_started")

    github = _build_github_client(installation_id)
    if repo_full_name and github:
        github.set_commit_status(
            repo_full_name, commit_sha, "pending",
            "aperIA: scanning in progress..."
        )

    repo_path = None
    try:
        # ── 1. Clone repo ──────────────────────────────────────────────
        repo_path = _clone_repo(repo_url, commit_sha, installation_id)
        log.info("repo_cloned", path=repo_path)

        effective_base_sha = base_sha or _get_parent_sha(repo_path, commit_sha)

        # ── 2. TruffleHog — prioridade máxima, bloqueia imediatamente ──
        th_findings = _run_trufflehog(
            repo_path, effective_base_sha, commit_sha, repo_url, log
        )
        verified_secrets = [f for f in th_findings if f.secret_verified]

        if verified_secrets and github and repo_full_name:
            github.block_merge(
                repo_full_name,
                commit_sha,
                f"CRITICAL: {len(verified_secrets)} verified secret(s) detected — immediate rotation required",
            )
            log.warning(
                "verified_secrets_detected_merge_blocked",
                count=len(verified_secrets),
            )

        # ── 3. Outros 6 scanners em paralelo ──────────────────────────
        parallel_findings = _run_parallel_scanners(
            repo_path, commit_sha, repo_url, log
        )

        # ── 4. Normalize + Deduplicate ─────────────────────────────────
        all_findings = th_findings + parallel_findings
        normalized = _deduplicator.deduplicate(all_findings)

        log.info(
            "pipeline_completed",
            raw_count=len(all_findings),
            deduplicated_count=len(normalized),
            verified_secrets=len(verified_secrets),
        )
        return normalized

    except Exception as exc:
        log.error("pipeline_failed", error=str(exc), exc_info=True)
        if github and repo_full_name:
            github.set_commit_status(
                repo_full_name, commit_sha, "error",
                f"aperIA: scan failed — {str(exc)[:100]}"
            )
        raise

    finally:
        if repo_path and os.path.exists(repo_path):
            _cleanup_repo(repo_path)


# ── Helpers ────────────────────────────────────────────────────────────────


def _build_github_client(installation_id: int | None) -> GitHubClient | None:
    try:
        if installation_id:
            token = get_installation_token(installation_id)
        else:
            token = settings.GITHUB_TOKEN
        return GitHubClient(token=token)
    except Exception as exc:
        logger.warning("github_client_init_failed", error=str(exc))
        return None


def _clone_repo(repo_url: str, commit_sha: str, installation_id: int | None) -> str:
    """Clona o repositório em diretório temporário e faz checkout do commit."""
    tmp = tempfile.mkdtemp(prefix="aperia-scan-")

    clone_url = repo_url
    if installation_id and settings.GITHUB_TOKEN:
        # Injeta token na URL para autenticação — nunca loga a URL completa
        clone_url = repo_url.replace(
            "https://github.com",
            f"https://x-access-token:{settings.GITHUB_TOKEN}@github.com",
        )

    try:
        subprocess.run(
            ["git", "clone", "--depth=50", clone_url, tmp],
            capture_output=True,
            timeout=120,
            check=True,
        )
        subprocess.run(
            ["git", "fetch", "--depth=1", "origin", commit_sha],
            cwd=tmp,
            capture_output=True,
            timeout=30,
            check=False,
        )
        subprocess.run(
            ["git", "checkout", commit_sha],
            cwd=tmp,
            capture_output=True,
            timeout=10,
            check=True,
        )
    except subprocess.CalledProcessError as exc:
        raise ScannerError(f"Falha ao clonar repositório: {exc}") from exc

    return tmp


def _get_parent_sha(repo_path: str, commit_sha: str) -> str:
    """Retorna o SHA do commit pai para o TruffleHog --since-commit."""
    result = subprocess.run(
        ["git", "rev-parse", f"{commit_sha}^"],
        cwd=repo_path,
        capture_output=True,
        text=True,
        timeout=5,
    )
    parent = result.stdout.strip()
    if len(parent) == 40:
        return parent
    return commit_sha  # root commit — usa o próprio


def _run_trufflehog(
    repo_path: str,
    base_sha: str,
    commit_sha: str,
    repo_url: str,
    log,
) -> list[Finding]:
    try:
        scanner = TruffleHogScanner()
        return scanner.scan(repo_path, base_sha, commit_sha, commit_sha, repo_url)
    except ScannerError as exc:
        log.error("trufflehog_failed", error=str(exc))
        return []


def _run_parallel_scanners(
    repo_path: str,
    commit_sha: str,
    repo_url: str,
    log,
) -> list[Finding]:
    """Executa Semgrep, Trivy, ZAP, OpenVAS, Wazuh, Prowler em paralelo."""
    tasks: dict[str, callable] = {
        "semgrep":  lambda: SemgrepScanner().scan(repo_path, ["."], commit_sha, repo_url),
        "trivy":    lambda: TrivyScanner().scan(repo_path, commit_sha, repo_url),
        "zap":      lambda: _run_zap_if_enabled(commit_sha, repo_url),
        "openvas":  lambda: _run_openvas_if_enabled(commit_sha, repo_url),
        "wazuh":    lambda: _run_wazuh_if_enabled(commit_sha, repo_url),
        "prowler":  lambda: ProwlerScanner().scan("aws", commit_sha, repo_url),
    }

    all_findings: list[Finding] = []
    with ThreadPoolExecutor(max_workers=6) as executor:
        futures = {executor.submit(fn): name for name, fn in tasks.items()}
        for future in as_completed(futures):
            name = futures[future]
            try:
                findings = future.result()
                all_findings.extend(findings)
                log.info(f"{name}_completed", count=len(findings))
            except Exception as exc:
                log.error(f"{name}_failed", error=str(exc))

    return all_findings


def _run_zap_if_enabled(commit_sha: str, repo_url: str) -> list[Finding]:
    target_url = getattr(settings, "ZAP_TARGET_URL", "")
    if not target_url:
        return []
    return ZAPScanner().scan(target_url, commit_sha, repo_url)


def _run_openvas_if_enabled(commit_sha: str, repo_url: str) -> list[Finding]:
    target_ip = getattr(settings, "OPENVAS_TARGET_IP", "")
    if not target_ip:
        return []
    return OpenVASScanner().scan(target_ip, commit_sha, repo_url)


def _run_wazuh_if_enabled(commit_sha: str, repo_url: str) -> list[Finding]:
    agent_id = getattr(settings, "WAZUH_AGENT_ID", "")
    if not agent_id:
        return []
    return WazuhScanner().get_vulnerabilities(agent_id, commit_sha, repo_url)


def _cleanup_repo(repo_path: str) -> None:
    import shutil
    try:
        shutil.rmtree(repo_path, ignore_errors=True)
    except Exception as exc:
        logger.warning("cleanup_failed", path=repo_path, error=str(exc))
