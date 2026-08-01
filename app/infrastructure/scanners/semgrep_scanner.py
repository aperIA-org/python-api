import re
import json
import subprocess

from app.domain.finding.entities import Finding
from app.domain.finding.value_objects import Severity, CVEId
from app.infrastructure.scanners.base_scanner import BaseScanner



def _normalizar_cwe(bruto: object) -> str | None:
    """Extrai o identificador CWE do metadado do Semgrep.

    O Semgrep devolve ``metadata["cwe"]`` como **lista** de frases descritivas,
    do tipo ``["CWE-79: Improper Neutralization of Input During Web Page
    Generation ('Cross-site Scripting')"]`` — enquanto o campo do domínio é um
    ``str`` e a coluna é ``VARCHAR(50)``.

    Isso quebrava a persistência com ``StringDataRightTruncation``, e como
    ``persist_findings`` é best-effort o pipeline seguia adiante: o finding
    aparecia no payload do canvas, alimentava o Tier 2, e nunca era gravado.
    No dashboard virava "nenhum finding" — indistinguível de repositório limpo.

    A frase completa continua disponível em ``raw_output``; aqui fica só o
    identificador (``CWE-79``), que é o que o campo significa e o que a UI
    exibe.
    """
    if isinstance(bruto, (list, tuple)):
        bruto = bruto[0] if bruto else None
    if not bruto:
        return None
    texto = str(bruto)
    achado = re.search(r"CWE-\d+", texto, re.IGNORECASE)
    return achado.group(0).upper() if achado else texto[:50]

class SemgrepScanner(BaseScanner):
    TIMEOUT = 180

    def scan(
        self,
        repo_path: str,
        changed_files: list[str],
        commit_sha: str,
        repo_url: str,
    ) -> list[Finding]:
        return self.scan_changed(repo_path, changed_files, commit_sha, repo_url)

    def scan_changed(
        self,
        repo_path: str,
        changed_files: list[str],
        commit_sha: str,
        repo_url: str,
    ) -> list[Finding]:
        """Roda o ruleset ``p/security-audit`` no escopo informado.

        ``changed_files`` vazio significa "não há diff a considerar" — scan
        manual de branch, ou PR cujo diff não pôde ser calculado. Nesse caso o
        alvo é a **árvore inteira** (``.``): antes este caminho devolvia ``[]``
        e o Tier 1 não analisava nada, o que fazia o pipeline inteiro concluir
        com zero findings.
        """
        alvos = changed_files or ["."]
        result = subprocess.run(
            ["semgrep", "--config=p/security-audit", "--json", "--quiet"] + alvos,
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=self.TIMEOUT,
        )
        raw = json.loads(result.stdout) if result.stdout else {"results": []}
        return [
            self._to_finding(r, commit_sha, repo_url, tier=1)
            for r in raw.get("results", [])
        ]

    def scan_expanded(
        self,
        repo_path: str,
        commit_sha: str,
        repo_url: str,
    ) -> list[Finding]:
        result = subprocess.run(
            ["semgrep", "--config=auto", "--json", "--quiet", "."],
            cwd=repo_path,
            capture_output=True,
            text=True,
            timeout=300,
        )
        raw = json.loads(result.stdout) if result.stdout else {"results": []}
        return [
            self._to_finding(r, commit_sha, repo_url, tier=2)
            for r in raw.get("results", [])
        ]

    def _to_finding(
        self, r: dict, commit_sha: str, repo_url: str, tier: int
    ) -> Finding:
        severity_map = {
            "ERROR": Severity.HIGH,
            "WARNING": Severity.MEDIUM,
            "INFO": Severity.LOW,
        }
        extra = r.get("extra", {})
        metadata = extra.get("metadata", {})
        cve_raw = metadata.get("cve")
        return Finding(
            source="semgrep",
            severity=severity_map.get(extra.get("severity", "INFO"), Severity.INFO),
            title=r.get("check_id", "unknown"),
            description=extra.get("message", ""),
            commit_sha=commit_sha,
            repo_url=repo_url,
            cve_id=CVEId(cve_raw) if cve_raw else None,
            cwe_id=_normalizar_cwe(metadata.get("cwe")),
            file_path=r.get("path"),
            line_number=r.get("start", {}).get("line"),
            raw_output=r,
            tier=tier,
        )
