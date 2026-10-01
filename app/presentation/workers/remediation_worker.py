"""Worker de remediação — gera patches para os findings de código do scan.

Entra no canvas logo depois de ``post_tier2_report`` e devolve ``analysis``
**inalterado**: o ``tier3_gate`` vem em seguida e decide a escalada em cima
dela. Este passo é um efeito colateral no meio da chain, não uma
transformação.

Quais findings entram, e por quê:

- **tier 1 e 2 apenas.** O Tier 3 é DAST: o ZAP reporta o mesmo alerta uma vez
  por rota, e um scan vira milhares de findings que são dezenas de problemas —
  sem arquivo nem linha onde ancorar um patch. Gerar patch para isso seria
  caro e inútil ao mesmo tempo.
- **com ``file_path`` e ``line_number``.** É o que a inline suggestion do
  GitHub exige, e é o que dá contexto de código ao prompt.
- **os mais graves primeiro, até ``REMEDIATION_MAX_PER_SCAN``.** Cada finding
  é uma chamada ao Claude.

Best-effort, como o resto do pipeline: qualquer falha vira log e o canvas
segue. O ``SuggestPatchUseCase`` já isola falha do Claude por finding e já é
idempotente por ``finding_id`` dentro do ``scan_job`` — re-scan não duplica
comentário no PR.
"""
from __future__ import annotations

from typing import Any, NamedTuple
from uuid import UUID

import structlog

from app.application.remediation.suggest_patch_use_case import (
    SuggestPatchCommand,
    SuggestPatchUseCase,
)
from app.config import settings
from app.core.celery_app import celery_app
from app.infrastructure.database.sqlalchemy import SessionLocal
from app.infrastructure.repositories.sqlalchemy_finding_repository import (
    SQLAlchemyFindingRepository,
)
from app.infrastructure.repositories.sqlalchemy_remediation_repository import (
    SQLAlchemyRemediationRepository,
)
from app.infrastructure.repositories.sqlalchemy_scan_job_repository import (
    SQLAlchemyScanJobRepository,
)

logger = structlog.get_logger()

#: Tiers cujos findings apontam para uma linha de código. O 3 fica de fora.
_TIERS_DE_CODIGO = (1, 2)

#: Ordem de atendimento. Quem não casa cai no fim.
_PESO_SEVERIDADE = {"critical": 0, "high": 1, "medium": 2, "low": 3, "info": 4}


#: Pastas que hospedam exemplo, não produção.
_PASTAS_DE_RUIDO = frozenset(
    {
        "test",
        "tests",
        "testing",
        "spec",
        "specs",
        "__tests__",
        "fixtures",
        "fixture",
        "doc",
        "docs",
        "example",
        "examples",
        "sample",
        "samples",
    }
)

#: Arquivos que são documentação, em qualquer lugar da árvore.
_EXTENSOES_DE_DOC = (".md", ".rst", ".txt", ".adoc")

#: Nomes de arquivo de teste, para as convenções que não usam pasta.
_PREFIXOS_DE_TESTE = ("test_", "conftest")
_SUFIXOS_DE_TESTE = ("_test.py", "_test.go", ".test.ts", ".test.js", ".spec.ts", ".spec.js")


def _e_exemplo(file_path: str) -> bool:
    """O arquivo é teste, fixture ou documentação?"""
    caminho = file_path.replace("\\", "/").lower()
    partes = caminho.split("/")
    nome = partes[-1]
    return (
        any(parte in _PASTAS_DE_RUIDO for parte in partes[:-1])
        or caminho.endswith(_EXTENSOES_DE_DOC)
        or nome.startswith(_PREFIXOS_DE_TESTE)
        or caminho.endswith(_SUFIXOS_DE_TESTE)
    )


def _e_ruido_de_secret(finding: dict[str, Any]) -> bool:
    """Secret NÃO verificado em arquivo de exemplo — não vale um patch.

    O TruffleHog marca como possível secret qualquer coisa com cara de
    credencial, e em teste e documentação isso é quase sempre um exemplo:
    `https://user:senha@host` num teste de parsing de URL, ou uma linha de
    tabela markdown listando esquemas inválidos. Não existe correção para
    falso positivo, e o modelo, obrigado a inventar uma, devolvia a linha
    inalterada ou pendurava um `# noqa` nela.

    As três condições são cumulativas de propósito. **`secret_verified` é a
    que não pode cair**: um secret confirmado vale em qualquer lugar —
    credencial viva num teste vaza igual, e esse caso chega a bloquear o
    Gate 1. Aqui só sai o que o scanner não conseguiu confirmar.
    """
    return (
        finding.get("source") == "trufflehog"
        and not finding.get("secret_verified")
        and _e_exemplo(str(finding.get("file_path") or ""))
    )


class Selecao(NamedTuple):
    """O que entra na remediação, e o que ficou pelo caminho."""

    itens: list[dict[str, Any]]
    #: Secrets não verificados em teste/doc — ver `_e_ruido_de_secret`.
    ruido: int
    #: Mesmo finding vindo de dois tiers — ver `_selecionar`.
    duplicados: int


def _selecionar(findings: list[Any], teto: int) -> Selecao:
    """Findings de código com âncora de arquivo, do mais grave ao menos.

    **A ordem das etapas é o que importa aqui, e cada uma custou um bug.**
    Deduplicar e filtrar ruído vêm ANTES do corte por teto: ao contrário, uma
    duplicata ou um falso positivo de documentação ocupa a vaga de um finding
    real, e o scan deixa de remediar o que importa sem nada no log explicando.

    A deduplicação existe porque `analysis["findings"]` junta T1 e T2, e o
    mesmo finding aparece nos dois. O `FindingDeduplicator` atua na
    persistência, não nesta lista. Sem o corte aqui, o candidato repetido
    chegava ao use case, era barrado pela idempotência por `finding_id` — e
    tinha consumido uma vaga do teto. Num scan real, 3 das 10 foram assim.

    Os contadores vão para o log: sem eles "não gerou patch" não se distingue
    de "não tinha o que gerar".
    """
    com_ancora = [
        f
        for f in findings
        if isinstance(f, dict)
        and f.get("tier") in _TIERS_DE_CODIGO
        and f.get("file_path")
        and f.get("line_number")
    ]

    # A `dedup_key` é a mesma chave da UNIQUE do banco — se dois candidatos a
    # compartilham, são a mesma linha de `findings`, viesse de que tier viesse.
    vistos: set[str] = set()
    distintos: list[dict[str, Any]] = []
    for finding in com_ancora:
        chave = _dedup_key(finding)
        if chave not in vistos:
            vistos.add(chave)
            distintos.append(finding)

    elegiveis = [f for f in distintos if not _e_ruido_de_secret(f)]
    elegiveis.sort(
        key=lambda f: _PESO_SEVERIDADE.get(str(f.get("severity", "")).lower(), 9)
    )
    return Selecao(
        itens=elegiveis[:teto],
        ruido=len(distintos) - len(elegiveis),
        duplicados=len(com_ancora) - len(distintos),
    )


def _dedup_key(finding: dict[str, Any]) -> str:
    """Reproduz ``Finding.dedup_key()`` a partir do dict do canvas.

    Tem que ficar igual a ``app/domain/finding/entities.py``: é a chave da
    UNIQUE ``findings_dedup_key``, e é por ela que se acha a linha persistida.
    """
    return (
        f"{finding.get('source')}:"
        f"{finding.get('cve_id') or finding.get('title')}:"
        f"{finding.get('file_path')}:{finding.get('line_number')}:"
        f"{finding.get('commit_sha')}"
    )


def _id_persistido(repo: SQLAlchemyFindingRepository, finding: dict[str, Any]) -> UUID | None:
    """O id da LINHA em ``findings``, que não é necessariamente o do dict.

    ``Remediation.finding_id`` é FK para ``findings.id``. O dict que trafega no
    canvas carrega o ``uuid4`` que a dataclass gerou em memória — e num
    **re-scan do mesmo commit** esse id nunca chegou ao banco: o
    ``ON CONFLICT DO NOTHING`` de ``bulk_save`` descartou o insert e a linha
    existente manteve o id antigo. Usar o id do canvas aí estoura a FK.

    ``None`` quando o finding não está no banco (persistência desligada, ou a
    gravação falhou) — sem linha de origem não há remediação a gravar.
    """
    linha = repo.find_duplicate(_dedup_key(finding))
    return linha.id if linha else None


@celery_app.task(
    name="app.presentation.workers.remediation_worker.suggest_remediations",
    bind=True,
    queue="reporting",
)
def suggest_remediations(
    self,
    analysis: dict[str, Any] | None,
    *,
    repo_full_name: str,
    pr_number: int | None,
    commit_sha: str,
    installation_id: int,
) -> dict[str, Any] | None:
    """Gera e posta os patches do scan. Devolve ``analysis`` sem tocar nela."""
    # Propagação de Ignore upstream (Gate 1 bloqueou) → no-op.
    if not analysis or not isinstance(analysis, dict):
        return None

    selecao = _selecionar(
        analysis.get("findings") or [], settings.REMEDIATION_MAX_PER_SCAN
    )
    selecionados = selecao.itens
    if not selecionados:
        logger.info(
            "remediations_sem_candidatos",
            commit_sha=commit_sha,
            descartados_por_ruido=selecao.ruido,
            duplicados=selecao.duplicados,
        )
        return analysis

    gerados = 0
    pulados = 0
    try:
        with SessionLocal() as db:
            job = SQLAlchemyScanJobRepository(db).get_by_commit(commit_sha)
            if job is None:
                logger.warning("remediations_sem_scan_job", commit_sha=commit_sha)
                return analysis

            findings_repo = SQLAlchemyFindingRepository(db)
            use_case = SuggestPatchUseCase(
                repository=SQLAlchemyRemediationRepository(db)
            )

            for finding in selecionados:
                finding_id = _id_persistido(findings_repo, finding)
                if finding_id is None:
                    pulados += 1
                    logger.info(
                        "remediation_finding_nao_persistido",
                        commit_sha=commit_sha,
                        title=str(finding.get("title"))[:80],
                    )
                    continue

                resultado = use_case.execute(
                    SuggestPatchCommand(
                        # O id do banco substitui o do canvas — ver
                        # ``_id_persistido``.
                        finding={**finding, "id": str(finding_id)},
                        scan_job_id=job.id,
                        repo_full_name=repo_full_name,
                        pr_number=pr_number,
                        commit_sha=commit_sha,
                        installation_id=installation_id,
                    )
                )
                if resultado.skipped:
                    pulados += 1
                else:
                    gerados += 1

            db.commit()
    except Exception as exc:  # noqa: BLE001
        # Best-effort: remediação é valor agregado, não pode derrubar o scan.
        logger.warning(
            "remediations_failed",
            commit_sha=commit_sha,
            error=str(exc),
            error_type=type(exc).__name__,
        )
        return analysis

    logger.info(
        "remediations_suggested",
        commit_sha=commit_sha,
        gerados=gerados,
        pulados=pulados,
        candidatos=len(selecionados),
        descartados_por_ruido=selecao.ruido,
        duplicados=selecao.duplicados,
    )
    return analysis
