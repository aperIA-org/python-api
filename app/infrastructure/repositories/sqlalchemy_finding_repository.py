from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime
from uuid import UUID

from sqlalchemy import case, func, nulls_last, select
from sqlalchemy.orm import Session

from app.domain.finding.entities import Finding
from app.domain.finding.repositories import FindingRepository
from app.infrastructure.persistence.models.finding_model import FindingModel
from app.infrastructure.persistence.models.scan_job_model import ScanJobModel


_INSERT_COLUMNS = (
    "id",
    "source",
    "severity",
    "tier",
    "title",
    "description",
    "cve_id",
    "cwe_id",
    "file_path",
    "line_number",
    "asset",
    "asset_criticality",
    "secret_verified",
    "secret_type",
    "raw_output",
    "commit_sha",
    "repo_url",
    "dedup_key",
    "created_at",
)


def _to_row(finding: Finding) -> dict:
    model = FindingModel.from_entity(finding)
    return {col: getattr(model, col) for col in _INSERT_COLUMNS}


def _build_filters(
    *,
    commit_sha: str | None,
    severity: str | None,
    tier: int | None,
    source: str | None,
    secret_verified: bool | None,
    title: str | None = None,
    user_id: UUID | None = None,
    repository_id: UUID | None = None,
) -> list:
    """Monta a lista de condições WHERE a partir dos filtros opcionais.

    Só inclui a condição quando o argumento correspondente não é ``None``.
    ``user_id``/``repository_id`` aplicam escopo multi-tenant: como findings
    não têm dono próprio, o escopo vem de um subquery em ``scan_jobs`` pelo
    ``commit_sha``.
    """
    filters = []
    if commit_sha is not None:
        filters.append(FindingModel.commit_sha == commit_sha)
    if severity is not None:
        filters.append(FindingModel.severity == severity)
    if tier is not None:
        filters.append(FindingModel.tier == tier)
    if source is not None:
        filters.append(FindingModel.source == source)
    if title is not None:
        # Igualdade exata: é o drill-down de um grupo, não busca livre.
        filters.append(FindingModel.title == title)
    if secret_verified is not None:
        filters.append(FindingModel.secret_verified.is_(secret_verified))
    if user_id is not None:
        filters.append(
            FindingModel.commit_sha.in_(
                select(ScanJobModel.commit_sha).where(ScanJobModel.user_id == user_id)
            )
        )
    if repository_id is not None:
        filters.append(
            FindingModel.commit_sha.in_(
                select(ScanJobModel.commit_sha).where(
                    ScanJobModel.repository_id == repository_id
                )
            )
        )
    return filters


# Teto de parâmetros por statement: o Postgres corta em 65535 (limite do
# protocolo wire) e o SQLite, dependendo da versão compilada, em 999. Usamos o
# piso conservador de cada dialeto.
#
# Isso não era um problema enquanto o ZAP colapsava centenas de alertas em 8
# findings. Quando o mapeamento passou a preservar a rota, um scan virou ~8.5k
# findings — 8474 × 19 colunas = 161k parâmetros num INSERT só, e o Tier 3
# inteiro era marcado como `failed` por causa da ESCRITA, com o scan já pronto.
_MAX_PARAMS = {"postgresql": 65535, "sqlite": 999}


def _em_lotes(rows: list[dict], dialect: str):
    """Fatia as linhas para nenhum statement estourar o teto de parâmetros."""
    colunas = max(1, len(rows[0]))
    por_lote = max(1, _MAX_PARAMS.get(dialect, 999) // colunas)
    for i in range(0, len(rows), por_lote):
        yield rows[i : i + por_lote]


@dataclass
class FindingGroup:
    """Um TIPO de vulnerabilidade, com todas as suas ocorrências somadas.

    Read model, não entidade: existe porque a lista crua deixou de ser legível.
    Um scan DAST do Juice Shop grava ~12 mil findings que são, na prática, 14
    problemas distintos repetidos por milhares de rotas — 3.007 ocorrências de
    "Cross-Domain Misconfiguration", uma por URL. Agregado, o mesmo conjunto
    cabe numa tela sem truncagem nenhuma.
    """

    source: str
    severity: str
    tier: int
    title: str
    cve_id: str | None
    cwe_id: str | None
    asset: str | None
    ocorrencias: int
    caminhos: int
    algum_secret_verificado: bool
    primeiro_em: datetime
    ultimo_em: datetime
    exemplo_finding_id: UUID
    # Primeiras ocorrências (caminho[:linha]), para a expansão do grupo na tela
    # sem precisar de uma segunda chamada.
    amostra: list[str] = field(default_factory=list)

    @property
    def chave(self) -> tuple:
        return (
            self.source,
            self.severity,
            self.tier,
            self.title,
            self.cve_id,
            self.cwe_id,
            self.asset,
        )


# Ordem de exibição: severidade primeiro, volume depois. Espelha SEV_ORDER no
# front — um grupo `info` com 3 mil ocorrências não pode encabeçar a lista.
_RANK_SEVERIDADE = case(
    (FindingModel.severity == "critical", 5),
    (FindingModel.severity == "high", 4),
    (FindingModel.severity == "medium", 3),
    (FindingModel.severity == "low", 2),
    else_=1,
)

_COLUNAS_GRUPO = (
    FindingModel.source,
    FindingModel.severity,
    FindingModel.tier,
    FindingModel.title,
    FindingModel.cve_id,
    FindingModel.cwe_id,
    FindingModel.asset,
)

# Nomes das colunas da chave. O agregado e a amostra PRECISAM usar a mesma
# tupla: quando a amostra indexava por um subconjunto, dois grupos que diferiam
# só no CWE colidiam — recebiam a amostra somada dos dois e o mesmo
# `exemplo_finding_id`, que pertencia a apenas um deles.
_NOMES_CHAVE = tuple(coluna.key for coluna in _COLUNAS_GRUPO)


def _chave(linha) -> tuple:
    return tuple(getattr(linha, nome) for nome in _NOMES_CHAVE)


class SQLAlchemyFindingRepository(FindingRepository):
    """Repositório síncrono — consumido pelos workers Celery (sync) via
    ``SessionLocal`` e pelos testes via uma ``Session`` sqlite.
    """

    def __init__(self, db: Session) -> None:
        self.db = db

    def save(self, finding: Finding) -> None:
        self.db.add(FindingModel.from_entity(finding))
        self.db.flush()

    def bulk_save(self, findings: list[Finding]) -> None:
        if not findings:
            return

        rows = [_to_row(f) for f in findings]
        dialect = self.db.bind.dialect.name if self.db.bind else "postgresql"

        # Os lotes correm na MESMA transação (quem chama é que dá commit),
        # então continua sendo tudo-ou-nada.
        if dialect == "postgresql":
            from sqlalchemy.dialects.postgresql import insert as pg_insert

            for lote in _em_lotes(rows, dialect):
                stmt = pg_insert(FindingModel).values(lote).on_conflict_do_nothing(
                    constraint="findings_dedup_key"
                )
                self.db.execute(stmt)
            return

        if dialect == "sqlite":
            from sqlalchemy.dialects.sqlite import insert as sqlite_insert

            for lote in _em_lotes(rows, dialect):
                stmt = sqlite_insert(FindingModel).values(lote).on_conflict_do_nothing(
                    index_elements=["dedup_key"]
                )
                self.db.execute(stmt)
            return

        # Fallback: insere um a um, ignora IntegrityError (defense-in-depth).
        from sqlalchemy.exc import IntegrityError

        for finding in findings:
            try:
                self.db.add(FindingModel.from_entity(finding))
                self.db.flush()
            except IntegrityError:
                self.db.rollback()

    def group_by_type(
        self,
        *,
        commit_sha: str | None = None,
        user_id: UUID | None = None,
        repository_id: UUID | None = None,
        amostra_por_grupo: int = 8,
        limit: int = 500,
    ) -> list[FindingGroup]:
        """Agrupa findings por tipo de vulnerabilidade.

        Duas consultas em vez de uma: a agregação e a amostra de ocorrências.
        Seria uma só com ``array_agg``, mas isso é exclusivo do Postgres e os
        testes rodam em SQLite. ``count(...).filter(...)`` e ``row_number()``
        existem nos dois — `bool_or`/`array_agg` não.

        Os filtros de tela (categoria, aging, texto livre, intervalo de datas)
        continuam no cliente: são multi-valor e a API não os expressa. O que
        muda é a ESCALA — o cliente passa a filtrar dezenas de grupos em vez de
        milhares de linhas cortadas em 1000.
        """
        filters = _build_filters(
            commit_sha=commit_sha,
            severity=None,
            tier=None,
            source=None,
            secret_verified=None,
            user_id=user_id,
            repository_id=repository_id,
        )

        agregado = self.db.execute(
            select(
                *_COLUNAS_GRUPO,
                func.count().label("ocorrencias"),
                func.count(func.distinct(FindingModel.file_path)).label("caminhos"),
                # `bool_or` não existe no SQLite; contar os verificados sim.
                func.count()
                .filter(FindingModel.secret_verified.is_(True))
                .label("verificados"),
                func.min(FindingModel.created_at).label("primeiro_em"),
                func.max(FindingModel.created_at).label("ultimo_em"),
            )
            .where(*filters)
            .group_by(*_COLUNAS_GRUPO)
            .order_by(_RANK_SEVERIDADE.desc(), func.count().desc())
            .limit(limit)
        ).all()

        if not agregado:
            return []

        # O id de exemplo sai daqui, não de um `min(id)` no agregado: o
        # Postgres não tem `min(uuid)` (o SQLite tem, porque guarda uuid como
        # texto — o teste passaria e a produção quebraria).
        amostras = self._amostra_por_grupo(filters, amostra_por_grupo)

        grupos = []
        for linha in agregado:
            exemplo_id, caminhos_amostra = amostras.get(_chave(linha), (None, []))
            if exemplo_id is None:
                continue  # grupo sem ocorrência legível: não há o que exibir
            grupos.append(
                FindingGroup(
                    source=linha.source,
                    severity=linha.severity,
                    tier=linha.tier,
                    title=linha.title,
                    cve_id=linha.cve_id,
                    cwe_id=linha.cwe_id,
                    asset=linha.asset,
                    ocorrencias=linha.ocorrencias,
                    caminhos=linha.caminhos,
                    algum_secret_verificado=linha.verificados > 0,
                    primeiro_em=linha.primeiro_em,
                    ultimo_em=linha.ultimo_em,
                    exemplo_finding_id=exemplo_id,
                    amostra=caminhos_amostra,
                )
            )
        return grupos

    def _amostra_por_grupo(
        self, filters: list, quantidade: int
    ) -> dict[tuple, tuple[UUID, list[str]]]:
        """Por grupo: o id de um finding representativo e os primeiros caminhos.

        ``row_number()`` particionado evita o N+1 de uma consulta por grupo. O
        mínimo é 1 mesmo com ``quantidade=0``, porque o id representativo é o
        que liga o grupo ao deep link de um finding.
        """
        quantidade = max(1, quantidade)

        # `nulls_last` explícito: sem ele o SQLite põe NULL primeiro e o
        # Postgres por último, então a amostra e o `exemplo_finding_id` de um
        # grupo com `file_path` nulo mudariam conforme o banco.
        posicao = (
            func.row_number()
            .over(
                partition_by=_COLUNAS_GRUPO,
                order_by=(
                    nulls_last(FindingModel.file_path),
                    nulls_last(FindingModel.line_number),
                ),
            )
            .label("posicao")
        )
        interno = (
            select(
                FindingModel.id,
                *_COLUNAS_GRUPO,
                FindingModel.file_path,
                FindingModel.line_number,
                posicao,
            )
            .where(*filters)
            .subquery()
        )

        amostras: dict[tuple, tuple[UUID, list[str]]] = {}
        for linha in self.db.execute(
            select(interno).where(interno.c.posicao <= quantidade).order_by(interno.c.posicao)
        ).all():
            chave = _chave(linha)
            caminho = linha.file_path or "(sem caminho)"
            if linha.line_number:
                caminho = f"{caminho}:{linha.line_number}"
            if chave not in amostras:
                amostras[chave] = (linha.id, [])
            amostras[chave][1].append(caminho)
        return amostras

    def get_by_commit(self, commit_sha: str) -> list[Finding]:
        result = self.db.execute(
            select(FindingModel).where(FindingModel.commit_sha == commit_sha)
        )
        return [m.to_entity() for m in result.scalars().all()]

    def get_verified_secrets(self, commit_sha: str) -> list[Finding]:
        result = self.db.execute(
            select(FindingModel).where(
                FindingModel.commit_sha == commit_sha,
                FindingModel.secret_verified.is_(True),
            )
        )
        return [m.to_entity() for m in result.scalars().all()]

    def find_duplicate(self, dedup_key: str) -> Finding | None:
        # dedup_key format: "source:cve_or_title:file_path:line_number:commit_sha"
        # Implementação simples: faz parse e busca. Em produção este método
        # raramente é chamado — bulk_save com ON CONFLICT é o caminho principal.
        parts = dedup_key.split(":", 4)
        if len(parts) != 5:
            return None
        source, key, file_path, line_str, commit_sha = parts
        try:
            line_number = int(line_str) if line_str != "None" else None
        except ValueError:
            return None
        result = self.db.execute(
            select(FindingModel).where(
                FindingModel.source == source,
                FindingModel.commit_sha == commit_sha,
                FindingModel.file_path == (file_path if file_path != "None" else None),
                FindingModel.line_number == line_number,
            )
        )
        model = result.scalars().first()
        return model.to_entity() if model else None

    def get_by_id(self, finding_id: UUID) -> Finding | None:
        """Busca um finding pelo seu identificador único."""
        result = self.db.execute(
            select(FindingModel).where(FindingModel.id == finding_id)
        )
        model = result.scalars().first()
        return model.to_entity() if model else None

    def query(
        self,
        *,
        commit_sha: str | None = None,
        severity: str | None = None,
        tier: int | None = None,
        source: str | None = None,
        secret_verified: bool | None = None,
        title: str | None = None,
        user_id: UUID | None = None,
        repository_id: UUID | None = None,
        limit: int = 50,
        offset: int = 0,
    ) -> list[Finding]:
        """Lista findings com filtros opcionais, ordenados do mais recente
        para o mais antigo, com paginação via ``limit``/``offset``.
        """
        filters = _build_filters(
            commit_sha=commit_sha,
            severity=severity,
            tier=tier,
            source=source,
            secret_verified=secret_verified,
            title=title,
            user_id=user_id,
            repository_id=repository_id,
        )
        stmt = (
            select(FindingModel)
            .where(*filters)
            .order_by(FindingModel.created_at.desc())
            .limit(limit)
            .offset(offset)
        )
        result = self.db.execute(stmt)
        return [m.to_entity() for m in result.scalars().all()]

    def count(
        self,
        *,
        commit_sha: str | None = None,
        severity: str | None = None,
        tier: int | None = None,
        source: str | None = None,
        secret_verified: bool | None = None,
        title: str | None = None,
        user_id: UUID | None = None,
        repository_id: UUID | None = None,
    ) -> int:
        """Conta findings que atendem aos filtros opcionais informados."""
        filters = _build_filters(
            commit_sha=commit_sha,
            severity=severity,
            tier=tier,
            source=source,
            secret_verified=secret_verified,
            title=title,
            user_id=user_id,
            repository_id=repository_id,
        )
        stmt = select(func.count()).select_from(FindingModel).where(*filters)
        return self.db.execute(stmt).scalar_one()

    def count_by_commits(
        self, commit_shas: list[str], *, user_id: UUID | None = None
    ) -> dict[str, int]:
        """Quantos findings cada commit tem, em UMA query agregada.

        Existe para a listagem de scans poder mostrar a contagem por execucao
        sem uma requisicao por card: sao ate' 200 scans por pagina, e um
        ``count`` por commit seria N+1 no caminho mais quente do dashboard.

        Commit sem finding nenhum NAO aparece no dicionario — quem chama
        distingue "zero findings" de "nao perguntamos", que sao coisas
        diferentes na tela. Escopo multi-tenant pelo ``user_id``, igual ao
        ``count``: o mesmo sha pode existir no scan de outro usuario (fork).
        """
        if not commit_shas:
            return {}

        filters = [FindingModel.commit_sha.in_(set(commit_shas))]
        if user_id is not None:
            filters.append(
                FindingModel.commit_sha.in_(
                    select(ScanJobModel.commit_sha).where(ScanJobModel.user_id == user_id)
                )
            )
        stmt = (
            select(FindingModel.commit_sha, func.count())
            .where(*filters)
            .group_by(FindingModel.commit_sha)
        )
        return {sha: total for sha, total in self.db.execute(stmt).all()}
