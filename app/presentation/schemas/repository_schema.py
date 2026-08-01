"""Schemas das rotas de repositórios GitHub ativados para análise."""

from __future__ import annotations

from datetime import datetime
from typing import Annotated
from uuid import UUID

from pydantic import BaseModel, BeforeValidator, Field, model_validator
from pydantic_core import PydanticCustomError

from app.domain.github.target_url import (
    TargetUrlInvalidaError,
    validar_target_url,
)


def _valida_target_url(valor: object) -> object:
    """Aplica a regra de domínio e traduz a recusa para erro Pydantic (422).

    Usa ``PydanticCustomError`` em vez de ``ValueError`` de propósito: o
    ``ValueError`` sai no 422 como ``"Value error, <msg>"`` e com
    ``type="value_error"`` para qualquer motivo. Com o erro customizado o
    front recebe a mensagem em português limpa em ``msg`` e um ``type``
    estável por motivo (``target_url_alvo_bloqueado``,
    ``target_url_esquema_invalido``, …), que dá para tratar sem casar string.
    """
    if valor is None:
        return None
    try:
        return validar_target_url(valor)
    except TargetUrlInvalidaError as exc:
        raise PydanticCustomError(exc.codigo, exc.mensagem) from exc


# ``BeforeValidator``: a regra roda sobre o valor cru, antes da coerção de
# tipo do Pydantic — inclusive para entradas que não são string.
TargetUrl = Annotated[str | None, BeforeValidator(_valida_target_url)]

_TARGET_URL_DESCRICAO = (
    "URL onde a aplicacao deste repositorio esta publicada (staging/preview). "
    "E o alvo do DAST (OWASP ZAP) no Tier 3; ausente/`null` significa 'sem "
    "deploy conhecido' e o ZAP e pulado. Apenas http/https absoluta e "
    "apontando para host publico."
)


class RepositoryResponse(BaseModel):
    """Repositório GitHub conectado ao aperIA, pertencente a um usuário."""

    id: UUID
    github_account_id: UUID
    installation_id: int
    github_repo_id: int
    full_name: str
    url: str | None
    default_branch: str
    active: bool
    # Sem default: na resposta a chave está SEMPRE presente (com `null` quando
    # não há alvo), então ela é `required` no schema e o front não precisa
    # tratar "campo ausente" como um terceiro estado.
    target_url: str | None = Field(
        description=_TARGET_URL_DESCRICAO,
        examples=["https://staging.suaempresa.com"],
    )
    created_at: datetime

    @classmethod
    def from_entity(cls, repo) -> "RepositoryResponse":
        return cls(
            id=repo.id,
            github_account_id=repo.github_account_id,
            installation_id=repo.installation_id,
            github_repo_id=repo.github_repo_id,
            full_name=repo.full_name,
            url=repo.url,
            default_branch=repo.default_branch,
            active=repo.active,
            target_url=repo.target_url,
            created_at=repo.created_at,
        )


class RepositoryCreate(BaseModel):
    """Payload para ativar um repositório GitHub para análise."""

    github_account_id: UUID
    github_repo_id: int
    full_name: str
    url: str
    default_branch: str = "main"
    target_url: TargetUrl = Field(
        default=None,
        description=(
            _TARGET_URL_DESCRICAO
            + " Como o POST e upsert, omitir o campo **preserva** a URL ja "
            "gravada; para remover use `PATCH` com `null`."
        ),
        examples=["https://staging.suaempresa.com"],
    )


class RepositoryUpdate(BaseModel):
    """Payload parcial: aplica **apenas** os campos presentes no JSON.

    Este schema exigia ``active`` obrigatório. Acrescentar ``target_url`` como
    segundo obrigatório quebraria o cliente atual, que envia
    ``{"active": false}``; e tornar os dois simplesmente opcionais criaria uma
    ambiguidade real em ``target_url``, onde ``null`` é um valor legítimo —
    "não mandei o campo" e "mandei null para limpar" chegariam idênticos
    (ambos ``None``).

    A saída é semântica explícita baseada em ``model_fields_set``, que o
    Pydantic preenche com as chaves **realmente presentes** no JSON:

    - chave ausente → campo não é tocado;
    - ``"target_url": "https://…"`` → define/atualiza o alvo;
    - ``"target_url": null`` → **limpa** o alvo (volta a pular o DAST);
    - ``"active": true|false`` → mesma semântica de sempre.

    Duas recusas explícitas, para que erro de cliente não vire no-op silencioso:
    corpo sem nenhum dos campos, e ``"active": null`` (não existe "limpar" um
    booleano ``NOT NULL``).
    """

    active: bool | None = Field(
        default=None,
        description="Ativa/desativa o monitoramento. Omitir = nao alterar. Nao aceita null.",
    )
    target_url: TargetUrl = Field(
        default=None,
        description=(
            _TARGET_URL_DESCRICAO
            + " Omitir = nao alterar; enviar `null` = remover o alvo."
        ),
        examples=["https://staging.suaempresa.com"],
    )

    @model_validator(mode="after")
    def _exige_intencao_explicita(self) -> "RepositoryUpdate":
        informados = self.model_fields_set
        if not informados:
            raise PydanticCustomError(
                "patch_sem_campos",
                "Informe ao menos um campo para atualizar: 'active' ou 'target_url'.",
            )
        if "active" in informados and self.active is None:
            raise PydanticCustomError(
                "active_nao_aceita_null",
                "O campo 'active' nao aceita null: envie true ou false, ou omita o campo.",
            )
        return self
