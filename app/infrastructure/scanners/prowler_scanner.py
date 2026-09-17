import json
import subprocess
from pathlib import Path

from app.domain.finding.entities import Finding
from app.domain.finding.value_objects import Severity
from app.infrastructure.scanners.base_scanner import BaseScanner


SEVERITY_MAP = {
    "critical": Severity.CRITICAL,
    "high": Severity.HIGH,
    "medium": Severity.MEDIUM,
    "low": Severity.LOW,
    "informational": Severity.INFO,
}

IAC_EXTENSIONS = {".tf", ".tfvars", ".yaml", ".yml", ".json"}
IAC_FILENAMES = {"Dockerfile", "docker-compose.yml", "docker-compose.yaml"}


def _e_iac(caminho: str) -> bool:
    return Path(caminho).suffix in IAC_EXTENSIONS or Path(caminho).name in IAC_FILENAMES


def has_iac_files(changed_files: list[str]) -> bool:
    return any(_e_iac(f) for f in changed_files)


def arvore_tem_iac(repo_path: str) -> bool:
    """Procura IaC na arvore inteira, para quando nao existe diff.

    `has_iac_files` decide pelo DIFF, e num scan manual de branch
    (`base_sha == commit_sha`) o diff e vazio — entao a condicao era sempre falsa
    e o Prowler nunca rodava, mesmo num repositorio cheio de Terraform, manifesto
    de Kubernetes e Dockerfile. Foi o caso medido no repo-alvo de demonstracao:
    `infra/terraform/main.tf`, `infra/k8s/deployment.yaml` e `Dockerfile`
    presentes, Prowler `skipped`.

    E o mesmo defeito que o `changed_files` vazio ja tinha causado no Semgrep, e
    a saida e a mesma que foi adotada la: sem diff contra o que comparar, o alvo
    passa a ser a arvore inteira. Errar para o lado de varrer demais custa tempo;
    errar para o lado de nao varrer custa a razao de existir do produto.

    `.git` fica de fora porque a arvore materializada o inclui, e um `.yaml`
    solto no diretorio de objetos nao e infraestrutura de ninguem.
    """
    raiz = Path(repo_path)
    for caminho in raiz.rglob("*"):
        if not caminho.is_file():
            continue
        if ".git" in caminho.relative_to(raiz).parts:
            continue
        if _e_iac(caminho.name):
            return True
    return False


class ProwlerScanner(BaseScanner):
    TIMEOUT = 600

    def scan(
        self,
        provider: str,
        commit_sha: str,
        repo_url: str,
        services: list[str] | None = None,
    ) -> list[Finding]:
        cmd = ["prowler", provider, "-M", "json", "--no-banner", "--quiet"]
        if services:
            cmd += ["-s", *services]

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=self.TIMEOUT,
        )
        findings: list[Finding] = []
        for line in result.stdout.splitlines():
            parsed = self._safe_parse(line)
            if parsed and parsed.get("Status") == "FAIL":
                findings.append(self._to_finding(parsed, commit_sha, repo_url))
        return findings

    def _safe_parse(self, line: str) -> dict | None:
        try:
            return json.loads(line)
        except json.JSONDecodeError:
            return None

    def _to_finding(
        self,
        item: dict,
        commit_sha: str,
        repo_url: str,
    ) -> Finding:
        severity_raw = str(item.get("Severity", "informational")).lower()
        return Finding(
            source="prowler",
            severity=SEVERITY_MAP.get(severity_raw, Severity.INFO),
            title=str(item.get("CheckTitle", "Prowler Check"))[:255],
            description=str(item.get("StatusExtended", ""))[:2000],
            commit_sha=commit_sha,
            repo_url=repo_url,
            asset=str(item.get("ResourceId", ""))[:500],
            raw_output=item,
            tier=2,
        )
