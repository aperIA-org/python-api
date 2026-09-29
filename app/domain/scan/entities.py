from dataclasses import dataclass, field
from uuid import UUID, uuid4
from datetime import datetime, timedelta

from app.domain.scan.value_objects import ScanTier, TierStatus

# Tiers ainda não concluídos: se algum tier está nesses estados, o pipeline
# daquele commit está na fila ou rodando.
STATUS_EM_ANDAMENTO = (TierStatus.QUEUED, TierStatus.RUNNING)

# Tiers que já têm um desfecho REAL — o tier rodou (ou falhou rodando). Uma
# decisão posterior de "skipped" não pode apagar isso.
STATUS_TERMINAIS = (TierStatus.DONE, TierStatus.FAILED)


@dataclass
class ScanJob:
    commit_sha: str
    repo_url: str
    installation_id: int
    id: UUID = field(default_factory=uuid4)
    pr_number: int | None = None
    repo_full_name: str | None = None
    tier1_status: TierStatus | None = None
    tier1_started_at: datetime | None = None
    tier1_completed_at: datetime | None = None
    tier2_status: TierStatus | None = None
    tier2_started_at: datetime | None = None
    tier2_completed_at: datetime | None = None
    tier3_status: TierStatus | None = None
    tier3_started_at: datetime | None = None
    tier3_completed_at: datetime | None = None
    blocked_at_tier: ScanTier | None = None
    final_risk_score: int | None = None
    final_risk_level: str | None = None
    # Multi-tenant: dono do scan (desnormalizado para filtro rápido) e
    # repositório conectado que o originou. Nullable p/ scans legados.
    # Id da raiz do canvas Celery. Sem ele não há como revogar o que ainda
    # não começou: o cancelamento só saberia mexer no banco.
    celery_task_id: str | None = None
    user_id: UUID | None = None
    repository_id: UUID | None = None
    created_at: datetime = field(default_factory=datetime.utcnow)

    def em_andamento(self) -> bool:
        """Verdadeiro se algum tier ainda está ``queued`` ou ``running``.

        É o que impede um novo disparo para o mesmo commit (409 em
        ``TriggerRepositoryScanUseCase``).
        """
        return any(
            status in STATUS_EM_ANDAMENTO
            for status in (self.tier1_status, self.tier2_status, self.tier3_status)
            if status is not None
        )

    def status_do_tier(self, tier: ScanTier) -> TierStatus | None:
        """Status do tier pedido, ou ``None`` se ele ainda não foi escrito."""
        return {
            ScanTier.ONE: self.tier1_status,
            ScanTier.TWO: self.tier2_status,
            ScanTier.THREE: self.tier3_status,
        }[tier]

    def tier_concluido(self, tier: ScanTier) -> bool:
        """Verdadeiro se o tier já chegou a um desfecho real (``done``/``failed``).

        É o que os gates consultam antes de registrar um ``skipped``: pular é
        uma decisão sobre um tier que NÃO rodou. Se ele rodou (retry do canvas,
        execução anterior, task fora de ordem), gravar ``skipped`` apagaria o
        resultado verdadeiro na projeção.
        """
        return self.status_do_tier(tier) in STATUS_TERMINAIS

    @property
    def ultimo_progresso_em(self) -> datetime:
        """Momento do último sinal de vida do pipeline deste commit.

        É o **mais recente** entre todos os ``tier*_started_at`` /
        ``tier*_completed_at`` e o ``created_at``. Cada transição de tier grava
        um desses timestamps, então o máximo deles é a última vez que alguém
        (worker ou API) tocou neste job.

        O ``created_at`` entra na conta porque existe o caso em que ele é o
        **único** timestamp disponível: a linha nasce com o Tier 1 já em
        ``running`` mas, se o processo morre antes do worker consumir a fila,
        nenhum ``tier*`` é escrito depois. Sem esse piso o job pareceria ter
        progresso desconhecido em vez de "parado desde a criação" — que é
        exatamente o cenário do incidente (Redis efêmero perdeu a fila).

        Todos os timestamps são naive em UTC (``datetime.utcnow``), igual ao
        resto da persistência de ``ScanJob``.
        """
        candidatos = [
            timestamp
            for timestamp in (
                self.tier1_started_at,
                self.tier1_completed_at,
                self.tier2_started_at,
                self.tier2_completed_at,
                self.tier3_started_at,
                self.tier3_completed_at,
                self.created_at,
            )
            if timestamp is not None
        ]
        return max(candidatos)

    def esta_travado(self, *, agora: datetime, limiar_minutos: int) -> bool:
        """Verdadeiro se o job diz estar em andamento mas não progride há muito.

        "Travado" (stale) = algum tier ``queued``/``running`` **e**
        ``ultimo_progresso_em`` mais velho que ``limiar_minutos``. Um job assim
        não vai ser concluído por ninguém: a tarefa Celery correspondente não
        existe mais (fila perdida, worker morto). Ele deve ser marcado como
        ``failed`` para não bloquear o commit para sempre.
        """
        if not self.em_andamento():
            return False
        return self.ultimo_progresso_em < agora - timedelta(minutes=limiar_minutos)
