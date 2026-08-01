"""Rotas de gerenciamento de repositórios GitHub ativados para análise.

Um repositório só pode ser ativado/gerenciado pelo usuário dono da conta
GitHub (instalação) à qual ele está vinculado. Ownership é sempre validado
comparando `user_id` — quando não pertence ao usuário logado, respondemos
404 (nunca 403) para não vazar a existência do recurso.
"""

from __future__ import annotations

from uuid import UUID

import structlog

from app.core.exceptions import ScanDispatchError

from fastapi import APIRouter, Depends, HTTPException, Query, status
from sqlalchemy.orm import Session

from app.application.exceptions import (
    GithubAppNotConfiguredError,
    GithubResolutionError,
    RepositoryInactiveError,
    ScanAlreadyInProgressError,
)
from app.application.use_cases.trigger_scan_use_case import (
    TriggerRepositoryScanUseCase,
)
from app.config import settings
from app.domain.github.entities import Repository
from app.infrastructure.database.sqlalchemy import get_db
from app.infrastructure.git.github_client import GitHubClient
from app.infrastructure.repositories.sqlalchemy_finding_repository import (
    SQLAlchemyFindingRepository,
)
from app.infrastructure.repositories.sqlalchemy_github_account_repository import (
    SQLAlchemyGithubAccountRepository,
)
from app.infrastructure.repositories.sqlalchemy_repository_repository import (
    SQLAlchemyRepositoryRepository,
)
from app.infrastructure.repositories.sqlalchemy_scan_job_repository import (
    SQLAlchemyScanJobRepository,
)
from app.infrastructure.repositories.sqlalchemy_scan_report_repository import (
    SQLAlchemyScanReportRepository,
)
from app.presentation.api.dependencies.auth import get_current_user
from app.presentation.schemas.finding_schema import (
    FindingPage,
    FindingResponse,
    FindingSeverity,
)
from app.presentation.schemas.repository_schema import (
    RepositoryCreate,
    RepositoryResponse,
    RepositoryUpdate,
)
from app.presentation.schemas.scan_schema import (
    ManualScanResponse,
    ScanJobPage,
    ScanJobSummary,
    ScanReportResponse,
)

logger = structlog.get_logger()

_UNAUTHORIZED_RESPONSE = {
    401: {
        "description": "Token ausente, invalido ou expirado.",
        "content": {"application/json": {"example": {"detail": "Credenciais invalidas ou token expirado."}}},
    }
}

router = APIRouter(
    prefix="/repositories",
    tags=["repositories"],
    dependencies=[Depends(get_current_user)],
    responses=_UNAUTHORIZED_RESPONSE,
)


@router.post(
    "",
    status_code=status.HTTP_201_CREATED,
    response_model=RepositoryResponse,
    summary="Ativar repositório para análise",
    responses={**_UNAUTHORIZED_RESPONSE, 404: {"description": "Conta GitHub nao encontrada."}},
)
def create_repository(
    payload: RepositoryCreate,
    user_id: UUID = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> RepositoryResponse:
    """Ativa um repositório GitHub para análise, vinculado a uma conta do usuário.

    A conta GitHub (`github_account_id`) precisa pertencer ao usuário logado;
    caso contrário retorna 404 (sem revelar se a conta existe para outro
    usuário).

    A operação é um **upsert** por `(user_id, github_repo_id)`: reativar um
    repositório desativado é um POST. A resposta traz o estado REAL persistido
    — em particular o `id` da linha existente, não o uuid gerado em memória
    (que não existiria no banco e faria `PATCH`/`DELETE` retornarem 404).

    `target_url` (opcional) é a URL onde a aplicação está publicada e vira o
    alvo do DAST no Tier 3. Ela passa pela validação anti-SSRF descrita em
    `PATCH /repositories/{id}` — URL malformada ou apontando para rede interna
    responde `422`. Por ser upsert, **omitir o campo preserva** a URL já
    gravada (senão um POST de reativação apagaria o alvo sem ninguém pedir);
    limpar é operação explícita do `PATCH` com `null`.
    """
    account = SQLAlchemyGithubAccountRepository(db).get_by_id(payload.github_account_id)
    if account is None or account.user_id != user_id:
        raise HTTPException(status_code=404, detail="Conta GitHub nao encontrada")

    repo = Repository(
        user_id=user_id,
        github_account_id=payload.github_account_id,
        installation_id=account.installation_id,
        github_repo_id=payload.github_repo_id,
        full_name=payload.full_name,
        url=payload.url,
        default_branch=payload.default_branch,
        active=True,
        target_url=payload.target_url,
    )
    persisted = SQLAlchemyRepositoryRepository(db).save(repo)
    db.commit()
    return RepositoryResponse.from_entity(persisted)


@router.get(
    "",
    response_model=list[RepositoryResponse],
    summary="Listar repositórios ativados",
)
def list_repositories(
    user_id: UUID = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[RepositoryResponse]:
    """Lista os repositórios GitHub ativados para análise pelo usuário logado."""
    repos = SQLAlchemyRepositoryRepository(db).list_by_user(user_id)
    return [RepositoryResponse.from_entity(r) for r in repos]


@router.get(
    "/{repository_id}",
    response_model=RepositoryResponse,
    summary="Detalhe de um repositório",
    responses={**_UNAUTHORIZED_RESPONSE, 404: {"description": "Repositorio nao encontrado."}},
)
def get_repository(
    repository_id: UUID,
    user_id: UUID = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> RepositoryResponse:
    """Retorna o detalhe de um repositório. 404 se não pertencer ao usuário."""
    repo = SQLAlchemyRepositoryRepository(db).get_by_id(repository_id)
    if repo is None or repo.user_id != user_id:
        raise HTTPException(status_code=404, detail="Repositorio nao encontrado")
    return RepositoryResponse.from_entity(repo)


@router.patch(
    "/{repository_id}",
    response_model=RepositoryResponse,
    summary="Atualizar repositório (ativação e/ou alvo de DAST)",
    responses={
        **_UNAUTHORIZED_RESPONSE,
        404: {"description": "Repositorio nao encontrado."},
        422: {
            "description": "Payload invalido (nenhum campo, `active: null` ou `target_url` recusada).",
            "content": {
                "application/json": {
                    # Mantém o schema padrão do FastAPI: sobrescrever a resposta
                    # 422 só para acrescentar exemplos apagaria o $ref.
                    "schema": {"$ref": "#/components/schemas/HTTPValidationError"},
                    "examples": {
                        "alvo_bloqueado": {
                            "summary": "URL aponta para a rede interna",
                            "value": {
                                "detail": [
                                    {
                                        "type": "target_url_alvo_bloqueado",
                                        "loc": ["body", "target_url"],
                                        "msg": "Alvo bloqueado: 169.254.169.254 aponta para a rede interna. Informe a URL publica do ambiente de staging/preview.",
                                    }
                                ]
                            },
                        },
                        "esquema_invalido": {
                            "summary": "Esquema fora de http/https",
                            "value": {
                                "detail": [
                                    {
                                        "type": "target_url_esquema_invalido",
                                        "loc": ["body", "target_url"],
                                        "msg": "Esquema 'file' nao e aceito: use http:// ou https://.",
                                    }
                                ]
                            },
                        },
                    }
                }
            },
        },
    },
)
def update_repository(
    repository_id: UUID,
    payload: RepositoryUpdate,
    user_id: UUID = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> RepositoryResponse:
    """Atualização **parcial**: aplica só os campos presentes no corpo.

    `404` se o repositório não existir ou não pertencer ao usuário (nunca 403).

    Semântica do corpo — `active` e `target_url` são independentes:

    - campo ausente → não é tocado;
    - `{"active": false}` → desativa (contrato inalterado, é o que o
      front-end já envia);
    - `{"target_url": "https://staging.acme.com"}` → define o alvo do DAST;
    - `{"target_url": null}` → **limpa** o alvo (o Tier 3 volta a pular o ZAP).

    `null` em `target_url` é valor legítimo, não omissão — por isso a rota
    decide por presença da chave (`model_fields_set`), não por "veio `None`".
    Corpo vazio e `{"active": null}` são `422` explícitos, para que um erro de
    cliente não passe como no-op silencioso.

    ## Por que `target_url` é validada com uma blocklist de rede

    O `target_url` não é um link exibido na UI: ele é entregue ao OWASP ZAP,
    que faz spider e **active scan** — dispara payloads reais de SQLi, XSS e
    path traversal contra tudo que encontrar. Aceitar URL arbitrária tem duas
    consequências diretas:

    1. **Ataque não autorizado a terceiros.** Cadastrar o site de outra
       empresa transformaria o aperIA na origem de um ataque, com o IP da
       nossa infraestrutura no log da vítima.
    2. **SSRF privilegiado.** O worker de Tier 3 roda dentro da nossa rede e
       alcança o que o usuário não alcança. `http://127.0.0.1:8090` é o
       próprio ZAP; `http://10.0.0.5` é banco/Redis; e
       `http://169.254.169.254` é o endpoint de metadata de AWS/GCP/Azure, que
       devolve **credenciais IAM temporárias da instância** — que voltariam ao
       usuário dentro dos findings do relatório.

    Por isso só passa URL http/https absoluta, sem credenciais embutidas, com
    host público: são recusados `localhost`, `127.0.0.0/8`, RFC1918
    (`10/8`, `172.16/12`, `192.168/16`), link-local `169.254.0.0/16` (o
    metadata incluso), CGNAT `100.64.0.0/10`, ULA/loopback IPv6, IPv4 mapeado
    em IPv6, as formas decimal/hexadecimal de IP (`http://2130706433`),
    sufixos internos (`.local`, `.internal`, `.localhost`) e hosts de rótulo
    único (`http://zap`), que só existem dentro da rede do worker.

    O que a validação **não** cobre, deliberadamente: um domínio público cujo
    DNS aponta para dentro (rebinding). Resolver DNS no cadastro seria TOCTOU
    — o registro muda entre validar e escanear — então a defesa desse vetor é
    de rede (egress policy no container do ZAP), não de schema.
    """
    repo_store = SQLAlchemyRepositoryRepository(db)
    repo = repo_store.get_by_id(repository_id)
    if repo is None or repo.user_id != user_id:
        raise HTTPException(status_code=404, detail="Repositorio nao encontrado")

    informados = payload.model_fields_set
    if "active" in informados:
        repo_store.set_active(repository_id, payload.active)
    if "target_url" in informados:
        # `None` aqui já é intenção explícita de limpar — o schema garantiu
        # que a chave veio no JSON.
        repo_store.set_target_url(repository_id, payload.target_url)
    db.commit()

    updated = repo_store.get_by_id(repository_id)
    return RepositoryResponse.from_entity(updated)


@router.delete(
    "/{repository_id}",
    status_code=status.HTTP_204_NO_CONTENT,
    summary="Remover repositório",
    responses={**_UNAUTHORIZED_RESPONSE, 404: {"description": "Repositorio nao encontrado."}},
)
def delete_repository(
    repository_id: UUID,
    user_id: UUID = Depends(get_current_user),
    db: Session = Depends(get_db),
):
    """Remove o vínculo do repositório. 404 se não pertencer ao usuário."""
    repo_store = SQLAlchemyRepositoryRepository(db)
    repo = repo_store.get_by_id(repository_id)
    if repo is None or repo.user_id != user_id:
        raise HTTPException(status_code=404, detail="Repositorio nao encontrado")

    repo_store.delete(repository_id)
    db.commit()


def _owned_repo_or_404(db: Session, repository_id: UUID, user_id: UUID) -> Repository:
    """Retorna o repositório se pertencer ao usuário; senão 404."""
    repo = SQLAlchemyRepositoryRepository(db).get_by_id(repository_id)
    if repo is None or repo.user_id != user_id:
        raise HTTPException(status_code=404, detail="Repositorio nao encontrado")
    return repo


@router.post(
    "/{repository_id}/scan",
    status_code=status.HTTP_202_ACCEPTED,
    response_model=ManualScanResponse,
    summary="Iniciar scan manual do repositório",
    responses={
        **_UNAUTHORIZED_RESPONSE,
        202: {
            "description": "Pipeline disparado para o HEAD do branch default.",
            "content": {
                "application/json": {
                    "example": {"status": "queued", "commit_sha": "9b2e1f0a", "branch": "main"}
                }
            },
        },
        404: {"description": "Repositorio nao encontrado."},
        409: {
            "description": "Repositorio desativado, ou scan já em andamento para o commit.",
            "content": {
                "application/json": {
                    "examples": {
                        "desativado": {
                            "summary": "Repositório desativado",
                            "value": {"detail": "Repositorio desativado: reative antes de iniciar um scan."},
                        },
                        "em_andamento": {
                            "summary": "Scan já rodando para o mesmo commit",
                            "value": {"detail": "Ja existe um scan em andamento para o commit 9b2e1f0a."},
                        },
                    }
                }
            },
        },
        502: {"description": "Falha ao consultar o GitHub para resolver o HEAD do branch."},
        503: {"description": "GitHub App nao configurado."},
    },
)
def trigger_repository_scan(
    repository_id: UUID,
    user_id: UUID = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> ManualScanResponse:
    """Dispara, sob demanda, o **mesmo** pipeline que o webhook de PR dispara.

    O commit analisado é o HEAD do `default_branch` do repositório, resolvido
    ao vivo no GitHub com o installation token. Como não há PR, o pipeline roda
    com `pr_number=None`: os relatórios ficam na projeção da API em vez de
    virarem comentário de PR.

    Contrato de erros:

    - `404` se o repositório não existir **ou** não pertencer ao usuário (nunca
      403 — não vazamos a existência do recurso).
    - `409` se o repositório estiver `active=false`. Desativado significa "não
      analisar": um scan manual aqui seria contraditório, e responder 404
      esconderia do usuário um repositório que ele mesmo pode reativar via
      `PATCH /repositories/{id}`. Por isso 409 com mensagem explícita.
    - `409` se já existir um `ScanJob` em andamento (algum tier `queued`/
      `running`) para o commit resolvido — evita duplicar o pipeline.
    - `502` se o GitHub não responder o HEAD do branch.
    - `503` se o GitHub App não estiver configurado (mesmo espírito do
      `GET /github/connect`, mas aqui o que falta são as credenciais do App —
      `GITHUB_APP_ID` / `GITHUB_PRIVATE_KEY_PATH` — necessárias para emitir o
      installation token).
    """
    repo = _owned_repo_or_404(db, repository_id, user_id)
    use_case = TriggerRepositoryScanUseCase(
        SQLAlchemyScanJobRepository(db),
        GitHubClient,
        github_app_configured=bool(
            settings.GITHUB_APP_ID and settings.GITHUB_PRIVATE_KEY_PATH
        ),
        commit=db.commit,
    )
    try:
        dispatch = use_case.execute(repo)
    except RepositoryInactiveError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except ScanAlreadyInProgressError as exc:
        raise HTTPException(status_code=409, detail=str(exc)) from exc
    except GithubAppNotConfiguredError as exc:
        raise HTTPException(status_code=503, detail=str(exc)) from exc
    except GithubResolutionError as exc:
        raise HTTPException(status_code=502, detail=str(exc)) from exc
    except ScanDispatchError as exc:
        # Nada foi enfileirado e nenhum ScanJob ficou pendurado (o orquestrador
        # encerra os tiers antes de propagar). Mensagem acionável em vez de um
        # 500 anônimo: o problema é de infraestrutura, e repetir faz sentido.
        logger.error("scan_manual_dispatch_falhou", repository_id=str(repository_id), error=str(exc))
        raise HTTPException(
            status_code=503,
            detail=(
                "Nao foi possivel enfileirar o scan: a fila de processamento nao "
                "respondeu. Nenhum scan foi iniciado. Tente novamente em alguns "
                "instantes; se persistir, verifique se o Redis e os workers estao no ar."
            ),
        ) from exc
    return ManualScanResponse(
        status=dispatch.status,
        commit_sha=dispatch.commit_sha,
        branch=dispatch.branch,
    )


@router.get(
    "/{repository_id}/scans",
    response_model=ScanJobPage,
    summary="Listar scans do repositório",
    responses={**_UNAUTHORIZED_RESPONSE, 404: {"description": "Repositorio nao encontrado."}},
)
def list_repository_scans(
    repository_id: UUID,
    user_id: UUID = Depends(get_current_user),
    db: Session = Depends(get_db),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> ScanJobPage:
    """Lista os scans (ScanJob) do repositório. 404 se não pertencer ao usuário."""
    _owned_repo_or_404(db, repository_id, user_id)
    repo = SQLAlchemyScanJobRepository(db)
    items = repo.list_by_repository(repository_id, limit=limit, offset=offset)
    total = repo.count_by_repository(repository_id)
    return ScanJobPage(
        items=[ScanJobSummary.from_entity(j) for j in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/{repository_id}/findings",
    response_model=FindingPage,
    summary="Listar findings do repositório",
    responses={**_UNAUTHORIZED_RESPONSE, 404: {"description": "Repositorio nao encontrado."}},
)
def list_repository_findings(
    repository_id: UUID,
    user_id: UUID = Depends(get_current_user),
    db: Session = Depends(get_db),
    severity: FindingSeverity | None = Query(None),
    tier: int | None = Query(None, ge=1, le=3),
    source: str | None = Query(None),
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
) -> FindingPage:
    """Lista os findings do repositório (todos os commits). 404 se não for do usuário."""
    _owned_repo_or_404(db, repository_id, user_id)
    repo = SQLAlchemyFindingRepository(db)
    sev = severity.value if severity else None
    items = repo.query(
        severity=sev, tier=tier, source=source,
        repository_id=repository_id, limit=limit, offset=offset,
    )
    total = repo.count(severity=sev, tier=tier, source=source, repository_id=repository_id)
    return FindingPage(
        items=[FindingResponse.from_entity(f) for f in items],
        total=total,
        limit=limit,
        offset=offset,
    )


@router.get(
    "/{repository_id}/reports",
    response_model=list[ScanReportResponse],
    summary="Listar relatórios do repositório",
    responses={**_UNAUTHORIZED_RESPONSE, 404: {"description": "Repositorio nao encontrado."}},
)
def list_repository_reports(
    repository_id: UUID,
    user_id: UUID = Depends(get_current_user),
    db: Session = Depends(get_db),
) -> list[ScanReportResponse]:
    """Lista os relatórios (por commit/tier) do repositório. 404 se não for do usuário."""
    _owned_repo_or_404(db, repository_id, user_id)
    reports = SQLAlchemyScanReportRepository(db).list_by_repository(repository_id)
    return [ScanReportResponse.from_entity(r) for r in reports]
