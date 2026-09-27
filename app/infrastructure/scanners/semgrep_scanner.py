import re
import json
import subprocess

import structlog

from app.domain.finding.entities import Finding
from app.domain.finding.value_objects import Severity, CVEId
from app.infrastructure.scanners.base_scanner import BaseScanner

logger = structlog.get_logger()


class SemgrepConfigError(RuntimeError):
    """O Semgrep nao conseguiu carregar as regras, entao nao varreu nada.

    Isto NAO e best-effort de proposito, e a excecao existe para o caso caber na
    regra do §10 da doc do pipeline: "perder finding e falha, nao aviso". Um erro
    de config faz o Semgrep sair com `results: []` e a lista vazia e
    indistinguivel de "repositorio limpo" — que num produto de seguranca e o pior
    desfecho possivel.

    Foi exatamente o que aconteceu: com o Semgrep pinado em 1.62.0, o registro
    passou a servir regras de severidade `MEDIUM`, aquela versao recusou a regra,
    e UMA regra invalida aborta a config inteira. O Tier 2 registrava `done` com
    0 findings sobre um repositorio com SQLi, XSS, SSRF e JWT quebrado.

    Levantar faz `run_safe` marcar a ferramenta como `failed` com o motivo. A
    tela passa a dizer "falhou" em vez de "concluida, nada encontrado", e as
    outras ferramentas seguem rodando.
    """


def _erros_de_config(raw: dict) -> list[str]:
    """Erros do Semgrep que significam "nao consegui carregar as regras".

    O Semgrep reporta problema de regra em `errors`, fora de `results`. O parser
    lia so `results`, entao esses erros eram invisiveis.

    Erro de config e diferente de erro de arquivo: um arquivo que nao parseia e
    normal (sintaxe quebrada, linguagem nao suportada) e nao invalida a varredura.
    Por isso o filtro e por tipo, nao "qualquer coisa em errors".
    """
    tipos_de_config = {"InvalidRuleSchemaError", "SemgrepError"}
    return [
        str(e.get("long_msg") or e.get("message") or _nome_do_tipo(e.get("type")))
        for e in raw.get("errors", []) or []
        if isinstance(e, dict) and _nome_do_tipo(e.get("type")) in tipos_de_config
    ]


def _nome_do_tipo(bruto: object) -> str:
    """Nome do construtor em ``errors[].type``.

    O Semgrep serializa variante de OCaml de duas formas: sem argumento vira
    string (``"SemgrepError"``), com argumento vira lista
    (``["PartialParsing", [{...}]]``). Testar a lista contra um ``set``
    levantava ``TypeError: unhashable type: 'list'`` **antes** de qualquer
    filtro, e o ``run_safe`` transformava isso em zero findings — ou seja,
    bastava um arquivo que não parseia (sintaxe quebrada, linguagem não
    suportada) para o Semgrep inteiro sumir do relatório como se o
    repositório estivesse limpo. Exatamente o que o filtro por tipo existe
    para evitar.
    """
    if isinstance(bruto, (list, tuple)):
        bruto = bruto[0] if bruto else None
    return str(bruto) if bruto is not None else ""



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
    # O escopo do Tier 2 e a arvore inteira, entao ele precisa de mais folga que
    # o Tier 1, que so olha os arquivos do diff.
    TIMEOUT_EXPANDED = 300

    # Ruleset por tier.
    #
    # O Tier 1 rodava `p/security-audit`, que e ESTREITO: medido contra o
    # repo-alvo de demonstracao, ele acha 5 dos 16 problemas plantados e deixa
    # passar SQL injection, XSS, JWT com `alg=none`, path traversal, SSRF e MD5 —
    # ou seja, a cabeca inteira da cadeia de ataque. `p/default` acha 40 no mesmo
    # repositorio, 21 deles ERROR (que vira `high` e faz o Gate 2 escalar).
    #
    # O Tier 2 segue em `auto`, que detecta as linguagens do repositorio e puxa
    # o conjunto correspondente. A diferenca entre os dois tiers e o ESCOPO
    # (diff contra arvore inteira), nao a profundidade da regra: um problema que
    # so o Tier 2 enxergasse ficaria invisivel no feedback rapido do PR, que e
    # justamente onde ele custa menos para corrigir.
    CONFIG_TIER1 = "p/default"
    CONFIG_TIER2 = "auto"

    # Ruleset de resgate quando o principal nao carrega. E estreito de proposito:
    # o que se quer dele e continuar entregando ALGUMA cobertura, e um ruleset
    # pequeno tem menos chance de trazer a regra que quebrou o principal.
    CONFIG_FALLBACK = "p/security-audit"

    def _rodar(
        self,
        config: str,
        alvos: list[str],
        repo_path: str,
        timeout: int,
        commit_sha: str,
    ) -> dict:
        """Roda o Semgrep e devolve o JSON, com resgate se as regras nao carregarem.

        Tenta o `config` pedido; se ele falhar por regra invalida, tenta o
        `CONFIG_FALLBACK`. Se os dois falharem, levanta — porque ai nao ha
        varredura nenhuma, e devolver `[]` afirmaria que o repositorio esta limpo.
        """
        for tentativa, cfg in enumerate((config, self.CONFIG_FALLBACK)):
            if tentativa and cfg == config:
                break  # fallback igual ao principal: nao ha o que tentar de novo
            result = subprocess.run(
                ["semgrep", f"--config={cfg}", "--json", "--quiet"] + alvos,
                cwd=repo_path,
                capture_output=True,
                text=True,
                timeout=timeout,
            )
            raw = json.loads(result.stdout) if result.stdout else {"results": []}
            erros = _erros_de_config(raw)
            if not erros:
                if tentativa:
                    logger.warning(
                        "semgrep_config_fallback_ok",
                        config_pedido=config,
                        config_usado=cfg,
                        commit_sha=commit_sha,
                        findings=len(raw.get("results", [])),
                    )
                return raw
            logger.warning(
                "semgrep_config_invalida",
                config=cfg,
                commit_sha=commit_sha,
                erros=erros[:3],
            )

        raise SemgrepConfigError(
            f"Semgrep nao carregou as regras nem com {config} nem com "
            f"{self.CONFIG_FALLBACK}: {'; '.join(erros[:2])}"
        )

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
        raw = self._rodar(
            config=self.CONFIG_TIER1,
            alvos=alvos,
            repo_path=repo_path,
            timeout=self.TIMEOUT,
            commit_sha=commit_sha,
        )
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
        raw = self._rodar(
            config=self.CONFIG_TIER2,
            alvos=["."],
            repo_path=repo_path,
            timeout=self.TIMEOUT_EXPANDED,
            commit_sha=commit_sha,
        )
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
        # Mesma variação do `cwe` logo abaixo: o Semgrep entrega esses
        # metadados ora como escalar, ora como lista.
        cve_raw = metadata.get("cve")
        if isinstance(cve_raw, (list, tuple)):
            cve_raw = cve_raw[0] if cve_raw else None
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
