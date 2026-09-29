"""
Schemas Pydantic (leitura) para status de scans (`ScanJob`).

Separados das entidades de dominio conforme Clean Architecture: aqui vivem
apenas os DTOs expostos pela API, com os metodos `from_entity` responsaveis
por converter enums de dominio (`TierStatus`, `ScanTier`) em valores
primitivos (`str`/`int`) prontos para serializacao JSON.
"""

from __future__ import annotations

from datetime import datetime
from uuid import UUID

from pydantic import BaseModel


class FindingsSummary(BaseModel):
    """Agregado de findings de um scan: por severidade, por tier e total."""

    by_severity: dict[str, int]
    by_tier: dict[str, int]
    total: int


class ScanJobResponse(BaseModel):
    """Representacao completa do status de um `ScanJob`, com resumo de findings."""

    # Identidade da EXECUÇÃO. O mesmo commit pode ter várias (rescan da mesma
    # branch), então `commit_sha` deixou de identificar um scan sozinho.
    id: UUID
    commit_sha: str
    repo_url: str
    repo_full_name: str | None
    pr_number: int | None
    tier1_status: str | None
    tier1_started_at: datetime | None
    tier1_completed_at: datetime | None
    tier2_status: str | None
    tier2_started_at: datetime | None
    tier2_completed_at: datetime | None
    tier3_status: str | None
    tier3_started_at: datetime | None
    tier3_completed_at: datetime | None
    blocked_at_tier: int | None
    final_risk_score: int | None
    final_risk_level: str | None
    created_at: datetime
    findings_summary: FindingsSummary

    @classmethod
    def from_entity(cls, job, summary: FindingsSummary) -> "ScanJobResponse":
        """Constroi o response a partir da entidade `ScanJob`, convertendo enums em valores."""
        return cls(
            id=job.id,
            commit_sha=job.commit_sha,
            repo_url=job.repo_url,
            repo_full_name=job.repo_full_name,
            pr_number=job.pr_number,
            tier1_status=job.tier1_status.value if job.tier1_status else None,
            tier1_started_at=job.tier1_started_at,
            tier1_completed_at=job.tier1_completed_at,
            tier2_status=job.tier2_status.value if job.tier2_status else None,
            tier2_started_at=job.tier2_started_at,
            tier2_completed_at=job.tier2_completed_at,
            tier3_status=job.tier3_status.value if job.tier3_status else None,
            tier3_started_at=job.tier3_started_at,
            tier3_completed_at=job.tier3_completed_at,
            blocked_at_tier=job.blocked_at_tier.value if job.blocked_at_tier else None,
            final_risk_score=job.final_risk_score,
            final_risk_level=job.final_risk_level,
            created_at=job.created_at,
            findings_summary=summary,
        )


class ScanJobSummary(BaseModel):
    """Versao enxuta de `ScanJobResponse`, usada em listagens.

    Nao carrega o `findings_summary` inteiro (por severidade e por tier) — isso e'
    do detalhe —, mas carrega o TOTAL: e' o numero que a lista de scans mostra por
    execucao, e ele tem de ser o mesmo que o detalhe do relatorio mostra, senao as
    duas telas do mesmo fluxo se contradizem. Vem de uma query agregada por
    commit, nao de um count por card.
    """

    # Identidade da EXECUÇÃO. O mesmo commit pode ter várias (rescan da mesma
    # branch), então `commit_sha` deixou de identificar um scan sozinho.
    id: UUID
    commit_sha: str
    repo_url: str
    repo_full_name: str | None
    pr_number: int | None
    tier1_status: str | None
    tier1_started_at: datetime | None
    tier1_completed_at: datetime | None
    tier2_status: str | None
    tier2_started_at: datetime | None
    tier2_completed_at: datetime | None
    tier3_status: str | None
    tier3_started_at: datetime | None
    tier3_completed_at: datetime | None
    blocked_at_tier: int | None
    final_risk_score: int | None
    final_risk_level: str | None
    created_at: datetime
    # `None` = nao contamos, e' diferente de zero. A tela some com o numero em
    # vez de afirmar "nenhum finding".
    findings_total: int | None = None

    @classmethod
    def from_entity(cls, job, findings_total: int | None = None) -> "ScanJobSummary":
        """Constroi o resumo a partir da entidade `ScanJob`, convertendo enums em valores."""
        return cls(
            id=job.id,
            commit_sha=job.commit_sha,
            repo_url=job.repo_url,
            repo_full_name=job.repo_full_name,
            pr_number=job.pr_number,
            tier1_status=job.tier1_status.value if job.tier1_status else None,
            tier1_started_at=job.tier1_started_at,
            tier1_completed_at=job.tier1_completed_at,
            tier2_status=job.tier2_status.value if job.tier2_status else None,
            tier2_started_at=job.tier2_started_at,
            tier2_completed_at=job.tier2_completed_at,
            tier3_status=job.tier3_status.value if job.tier3_status else None,
            tier3_started_at=job.tier3_started_at,
            tier3_completed_at=job.tier3_completed_at,
            blocked_at_tier=job.blocked_at_tier.value if job.blocked_at_tier else None,
            final_risk_score=job.final_risk_score,
            final_risk_level=job.final_risk_level,
            created_at=job.created_at,
            findings_total=findings_total,
        )


class ScanJobPage(BaseModel):
    """Pagina de resultados da listagem de scans recentes."""

    items: list[ScanJobSummary]
    total: int
    limit: int
    offset: int


class ScanReportResponse(BaseModel):
    """Representacao de um `ScanReport` (relatorio markdown de um tier).

    Carrega `scan_id`/`commit_sha` porque a listagem por repositorio mistura
    execucoes: sem eles, dois relatorios de tier 2 do mesmo commit sao
    indistinguiveis.
    """

    scan_id: UUID
    commit_sha: str
    tier: int
    report_markdown: str
    analysis_json: dict
    degraded: bool
    comment_id: int | None
    posted: bool
    created_at: datetime

    @classmethod
    def from_entity(cls, report) -> "ScanReportResponse":
        """Constroi o response a partir da entidade `ScanReport`."""
        return cls(
            scan_id=report.scan_job_id,
            commit_sha=report.commit_sha,
            tier=report.tier,
            report_markdown=report.report_markdown,
            analysis_json=report.analysis_json,
            degraded=report.degraded,
            comment_id=report.comment_id,
            posted=report.posted,
            created_at=report.created_at,
        )


class ScanReportsResponse(BaseModel):
    """Lista de relatorios (um por tier) de UMA execucao."""

    scan_id: UUID
    commit_sha: str
    reports: list[ScanReportResponse]


class ManualScanResponse(BaseModel):
    """Aceite de um scan manual (`POST /repositories/{id}/scan`).

    No espirito da resposta do webhook (`{"status": "queued", "commit_sha": ...}`),
    acrescentando o `branch` cujo HEAD foi resolvido.
    """

    status: str
    commit_sha: str
    branch: str


class ScanToolRunResponse(BaseModel):
    """Desfecho de UMA ferramenta do pipeline dentro de uma execucao.

    `status` acompanha os valores de tier (`queued`/`running`/`done`/`failed`/
    `skipped`) e acrescenta `degraded`, que so existe no nivel da ferramenta:
    os passos de I.A caem para uma heuristica quando o Claude falha e o tier
    fecha como `done` mesmo assim.

    `findings_count` e' `null` quando a ferramenta nao produz finding (I.A,
    threat intel, Caldera) — diferente de `0`, que significa "rodou e nao achou
    nada". Essa diferenca e' justamente o que a tabela existe para guardar.
    """

    tier: int
    tool: str
    status: str
    reason: str | None
    findings_count: int | None
    duration_ms: int | None
    started_at: datetime | None
    completed_at: datetime | None

    @classmethod
    def from_entity(cls, run) -> "ScanToolRunResponse":
        """Constroi o response a partir da entidade `ScanToolRun`."""
        return cls(
            tier=run.tier,
            tool=run.tool,
            status=run.status.value,
            reason=run.reason,
            findings_count=run.findings_count,
            duration_ms=run.duration_ms,
            started_at=run.started_at,
            completed_at=run.completed_at,
        )


# ─────────────────────────── Camada de I.A (Tier 3) ───────────────────────────
#
# O `analysis_json` do relatorio de tier 3 e' JSON PRODUZIDO POR LLM e carrega,
# alem do raciocinio, o array `findings` inteiro com o `raw_output` de cada um —
# centenas de KB. A lista de Scans do dashboard chama `GET /scans/{id}/tools`
# uma vez por card (ate' 12), entao devolver o blob cru seriam megabytes por
# tela. Os schemas abaixo resumem so' o que a UI desenha; `findings`,
# `validacao_evidencia` e `prioritized_actions` NUNCA saem daqui.
#
# Todo campo e' tratado como NAO CONFIAVEL: o modelo pode omitir chave, mandar
# `null`, string onde se espera lista, lista onde se espera objeto. Um blob
# malformado tem que degradar para um resumo vazio, nunca virar 500 — mesma
# filosofia best-effort do pipeline. Por isso os helpers com `isinstance` em vez
# de `try/except` em volta de tudo: assim cada campo degrada sozinho e os
# vizinhos sobrevivem.


def _dict_ou_vazio(valor: object) -> dict:
    """Devolve `valor` se for dict, senao `{}` (cobre `null` e tipo errado)."""
    return valor if isinstance(valor, dict) else {}


def _lista_ou_vazia(valor: object) -> list:
    """Devolve `valor` se for lista, senao `[]` (o modelo ja' mandou string aqui)."""
    return valor if isinstance(valor, list) else []


def _bool_ou_falso(valor: object) -> bool:
    """Converte para bool de forma conservadora.

    Aceita o booleano de verdade, o 0/1 que alguns modelos emitem e as strings
    `"true"`/`"false"` — `bool("false")` seria `True`, que e' exatamente o
    erro que este helper existe para evitar.
    """
    if isinstance(valor, bool):
        return valor
    if isinstance(valor, (int, float)):
        return bool(valor)
    if isinstance(valor, str):
        return valor.strip().lower() in {"true", "1", "yes", "sim"}
    return False


def _str_ou_none(valor: object) -> str | None:
    """So' aceita string nao vazia. Nao serializa dict/lista em texto."""
    if isinstance(valor, str):
        texto = valor.strip()
        return texto or None
    return None


def _int_ou_none(valor: object) -> int | None:
    """Aceita int, float (trunca) e string numerica; qualquer outra coisa e' None."""
    if isinstance(valor, bool):
        return None
    if isinstance(valor, int):
        return valor
    if isinstance(valor, float):
        return int(valor)
    if isinstance(valor, str):
        try:
            return int(float(valor.strip()))
        except ValueError:
            return None
    return None


def _float_ou_none(valor: object) -> float | None:
    """Idem `_int_ou_none`, preservando a fracao (EPSS e' 0.0–1.0)."""
    if isinstance(valor, bool):
        return None
    if isinstance(valor, (int, float)):
        return float(valor)
    if isinstance(valor, str):
        try:
            return float(valor.strip())
        except ValueError:
            return None
    return None


def _lista_de_str(valor: object) -> list[str]:
    """Normaliza uma lista heterogenea de TTPs em strings nao vazias."""
    itens: list[str] = []
    for item in _lista_ou_vazia(valor):
        if isinstance(item, str):
            texto = item.strip()
        elif isinstance(item, (int, float)) and not isinstance(item, bool):
            texto = str(item)
        else:
            continue
        if texto:
            itens.append(texto)
    return itens


class ScanIaPath(BaseModel):
    """Um passo do attack path que o Claude montou no Tier 3.

    `finding_count` substitui o `finding_ids` do blob de proposito: aquela lista
    guarda strings longas legiveis por humano (`"trufflehog: Possivel secret
    (nao verificado): Github (README.md:184)"`), uma por finding do passo. A UI
    so' precisa de quantos sao, e devolver as strings inflaria a resposta sem
    ninguem consumir.
    """

    step: int
    phase: str
    technique: str
    description: str
    finding_count: int
    caldera_validated: bool


class ScanIaChainStep(BaseModel):
    """Um passo de uma cadeia de ataque.

    `outcome` e' o campo que mais importa e o mais facil de achatar: as quatro
    opcoes dizem coisas DIFERENTES. `emulado` = o Caldera executou o movimento e
    ele funcionou; `bloqueado` = executou e um controle conteve — uma DEFESA que
    funcionou, nao uma falha de dado; `nao_emulado` = o Caldera nao teve como
    tentar (sem alvo, sem agente); `projecao` = ninguem executou, e' inferencia
    do modelo. O `caldera_validated` booleano de `attack_path` confundia os tres
    ultimos num unico `false`.
    """

    phase: str | None
    tactic: str | None
    technique: str | None
    asset: str | None
    outcome: str | None
    evidence: str | None


class ScanIaChain(BaseModel):
    """Uma cadeia de ataque de ponta a ponta, com os passos em ordem."""

    title: str | None
    severity: str | None
    steps: list[ScanIaChainStep]


class ScanIaCti(BaseModel):
    """Threat intel (KEV + EPSS + OpenCTI) que alimentou a analise.

    `status` e' o flag deterministico que o worker grava ("a fonte respondeu?"),
    nao a leitura do modelo sobre a ameaca.
    """

    status: str | None
    known_exploited: bool
    epss_score: float | None
    active_threat: bool
    mitre_techniques: list[str]


class ScanIaCaldera(BaseModel):
    """Resultado da emulacao adversaria (Caldera).

    `status` vem de `caldera_results["status"]`, cujo valor de sucesso e'
    `"reachable"`; `partial` (`validacao_parcial`) marca a emulacao que executou
    mas nao provou exploracao — a distincao que o reporting worker tambem
    respeita para nao afirmar exploracao bem-sucedida.
    """

    status: str | None
    techniques_executed: int
    techniques_successful: int
    validated: bool
    partial: bool
    ttps: list[str]


class ScanIaVerdict(BaseModel):
    """Leitura executiva do Tier 3: o que decidir sobre este commit.

    `recommendation` e' um enum curto de proposito. A tela colore e prioriza por
    ele, e ter que descobrir em prosa se o veredito era "bloquear" seria fragil —
    a `headline` e' a frase para o humano, nao o dado que a UI interpreta.
    """

    recommendation: str | None
    headline: str | None


class ScanIaEffort(BaseModel):
    """Esforco de correcao, estimado pelo Tier 3 a partir dos proprios findings.

    Nao e' estimativa de sprint: sai de quantos arquivos e componentes os
    findings tocam, que e' o que o modelo de fato viu.
    """

    level: str | None
    label: str | None


class ScanIaDeadline(BaseModel):
    """Prazo recomendado, em dias corridos contados da analise.

    Guardamos o numero E o texto: `days` serve para ordenar e comparar, `label`
    e' o que a tela mostra sem ter que reformatar (e errar) o plural.
    """

    days: int | None
    label: str | None


class ScanIaImpactArea(BaseModel):
    """Um efeito de negocio dos findings deste commit.

    `area` e `severity` sao enums curtos porque a tela colore e ordena por eles;
    `title`/`detail` sao o texto para o humano. Area desconhecida NAO e' descartada
    — chega crua para a UI, que mostra o id em vez de sumir com o efeito.
    """

    area: str | None
    severity: str | None
    title: str | None
    detail: str | None


class ScanIaImpactNote(BaseModel):
    """Um par titulo/detalhe da faixa de consequencias ("se corrigir agora"...)."""

    headline: str | None
    detail: str | None


class ScanIaBusinessImpact(BaseModel):
    """A traducao do risco tecnico para quem decide.

    E' o bloco que responde "o que isso significa para a empresa" sem CVE, sem TTP
    e sem nome de ferramenta. Vem do `analysis_json` do Tier 3; relatorio anterior
    a esta versao do prompt sai `None`, e `None` e' "ninguem traduziu".
    """

    headline: str | None
    areas: list[ScanIaImpactArea]
    if_fixed_now: ScanIaImpactNote | None
    if_deferred: ScanIaImpactNote | None
    regulatory: ScanIaImpactNote | None


class ScanIaSummary(BaseModel):
    """Resumo COMPACTO da camada de I.A do Tier 3, derivado do `analysis_json`.

    `degraded=True` com `reason` preenchido e' o caso real em que o Claude falhou
    e o worker gravou so' `reason`/`cti_data`/`degraded`/`findings`: sem
    `attack_path`, sem `risk_score_adjusted`, sem `caldera_results`. Nesse blob
    `paths` sai `[]` e os blocos ausentes saem `None` — e' informacao, nao erro.
    """

    degraded: bool
    reason: str | None
    kill_chain_complete: bool
    risk_level: str | None
    risk_score: int | None
    paths: list[ScanIaPath]
    # As cadeias agrupadas, que sao o que a tela desenha. `paths` (lista plana)
    # continua para os relatorios anteriores a esta versao do prompt: sem
    # `attack_chains`, a tela cai nela e monta uma cadeia sem titulo.
    chains: list[ScanIaChain]
    cti: ScanIaCti | None
    caldera: ScanIaCaldera | None
    # Os tres abaixo sao a leitura executiva, e chegaram DEPOIS: relatorio
    # gerado antes dessa versao do prompt nao tem as chaves, e sai `None`.
    # `None` e' "ninguem calculou" — a tela diz isso, nao um valor de fachada.
    verdict: ScanIaVerdict | None
    effort: ScanIaEffort | None
    deadline: ScanIaDeadline | None
    impact: ScanIaBusinessImpact | None

    @classmethod
    def from_analysis(cls, analysis_json: object) -> "ScanIaSummary":
        """Constroi o resumo a partir do `analysis_json` bruto do relatorio tier 3.

        Nao levanta: recebe `object` (o proprio blob pode nao ser um dict) e cada
        campo cai para o seu default quando o tipo nao bate.
        """
        analysis = _dict_ou_vazio(analysis_json)
        risco = _dict_ou_vazio(analysis.get("risk_score_adjusted"))

        return cls(
            degraded=_bool_ou_falso(analysis.get("degraded")),
            reason=_str_ou_none(analysis.get("reason")),
            kill_chain_complete=_bool_ou_falso(analysis.get("kill_chain_complete")),
            risk_level=_str_ou_none(risco.get("level")),
            risk_score=_int_ou_none(risco.get("score")),
            paths=cls._paths(analysis.get("attack_path")),
            chains=cls._chains(analysis.get("attack_chains")),
            cti=cls._cti(analysis),
            caldera=cls._caldera(analysis),
            verdict=cls._verdict(analysis),
            effort=cls._effort(analysis),
            deadline=cls._deadline(analysis),
            impact=cls._impact(analysis),
        )

    @staticmethod
    def _paths(attack_path: object) -> list[ScanIaPath]:
        """Normaliza `attack_path`, ignorando itens que nao sao objetos."""
        passos: list[ScanIaPath] = []
        for indice, item in enumerate(_lista_ou_vazia(attack_path)):
            if not isinstance(item, dict):
                continue
            # Sem `step` utilizavel usamos a posicao: um passo sem numero ainda
            # e' um passo, e a UI ordena por ele.
            numero = _int_ou_none(item.get("step"))
            passos.append(
                ScanIaPath(
                    step=numero if numero is not None else indice + 1,
                    phase=_str_ou_none(item.get("phase")) or "",
                    technique=_str_ou_none(item.get("technique")) or "",
                    description=_str_ou_none(item.get("description")) or "",
                    finding_count=len(_lista_ou_vazia(item.get("finding_ids"))),
                    caldera_validated=_bool_ou_falso(item.get("caldera_validated")),
                )
            )
        return passos

    @staticmethod
    def _chains(valor: object) -> list[ScanIaChain]:
        """Normaliza `attack_chains`, descartando o que nao e' cadeia utilizavel.

        Cadeia sem passo nenhum nao e' cadeia — sai da lista. Passo sem fase E sem
        tecnica tambem: seria uma linha vazia no trilho.
        """
        cadeias: list[ScanIaChain] = []
        for item in _lista_ou_vazia(valor):
            if not isinstance(item, dict):
                continue
            passos: list[ScanIaChainStep] = []
            for passo in _lista_ou_vazia(item.get("steps")):
                if not isinstance(passo, dict):
                    continue
                fase = _str_ou_none(passo.get("phase"))
                tecnica = _str_ou_none(passo.get("technique"))
                if fase is None and tecnica is None:
                    continue
                passos.append(
                    ScanIaChainStep(
                        phase=fase,
                        tactic=_str_ou_none(passo.get("tactic")),
                        technique=tecnica,
                        asset=_str_ou_none(passo.get("asset")),
                        outcome=_str_ou_none(passo.get("outcome")),
                        evidence=_str_ou_none(passo.get("evidence")),
                    )
                )
            if not passos:
                continue
            cadeias.append(
                ScanIaChain(
                    title=_str_ou_none(item.get("title")),
                    severity=_str_ou_none(item.get("severity")),
                    steps=passos,
                )
            )
        return cadeias

    @staticmethod
    def _cti(analysis: dict) -> ScanIaCti | None:
        """`None` quando nao ha' nem `cti_data` com conteudo nem `cti_status`.

        Sem nenhum dos dois nao temos o que afirmar sobre threat intel — e' bem
        diferente de "consultamos e nao ha' ameaca ativa", que sai como bloco
        preenchido com os flags em `false`.
        """
        dados = _dict_ou_vazio(analysis.get("cti_data"))
        status = _str_ou_none(analysis.get("cti_status"))
        if not dados and status is None:
            return None
        return ScanIaCti(
            status=status,
            known_exploited=_bool_ou_falso(dados.get("known_exploited")),
            epss_score=_float_ou_none(dados.get("epss_score")),
            active_threat=_bool_ou_falso(dados.get("active_threat")),
            mitre_techniques=_lista_de_str(dados.get("mitre_techniques")),
        )

    @staticmethod
    def _caldera(analysis: dict) -> ScanIaCaldera | None:
        """`None` quando nao ha' nem `caldera_results` com conteudo nem `caldera_status`.

        Mesma regra do CTI: o blob degradado pode nao ter emulacao nenhuma, e
        inventar um bloco zerado faria "nao rodou" parecer "rodou e falhou".
        """
        dados = _dict_ou_vazio(analysis.get("caldera_results"))
        status_top = _str_ou_none(analysis.get("caldera_status"))
        if not dados and status_top is None:
            return None
        return ScanIaCaldera(
            status=_str_ou_none(dados.get("status")) or status_top,
            techniques_executed=_int_ou_none(dados.get("techniques_executed")) or 0,
            techniques_successful=_int_ou_none(dados.get("techniques_successful")) or 0,
            validated=_bool_ou_falso(dados.get("caldera_validated")),
            partial=_bool_ou_falso(dados.get("validacao_parcial")),
            ttps=_lista_de_str(dados.get("ttps_used")),
        )

    @staticmethod
    def _verdict(analysis: dict) -> "ScanIaVerdict | None":
        """`None` quando o blob nao tem veredito — o caso de todo relatorio
        gerado antes de o prompt pedir a chave, e do caminho degradado."""
        dados = _dict_ou_vazio(analysis.get("executive_verdict"))
        recomendacao = _str_ou_none(dados.get("recommendation"))
        headline = _str_ou_none(dados.get("headline"))
        if recomendacao is None and headline is None:
            return None
        return ScanIaVerdict(recommendation=recomendacao, headline=headline)

    @staticmethod
    def _effort(analysis: dict) -> "ScanIaEffort | None":
        """Mesma regra do veredito: bloco vazio e' ausencia, nao zero."""
        dados = _dict_ou_vazio(analysis.get("remediation_effort"))
        nivel = _str_ou_none(dados.get("level"))
        label = _str_ou_none(dados.get("label"))
        if nivel is None and label is None:
            return None
        return ScanIaEffort(level=nivel, label=label)

    @staticmethod
    def _nota(valor: object) -> "ScanIaImpactNote | None":
        """Par titulo/detalhe; `None` quando os dois vem vazios."""
        dados = _dict_ou_vazio(valor)
        headline = _str_ou_none(dados.get("headline"))
        detail = _str_ou_none(dados.get("detail"))
        if headline is None and detail is None:
            return None
        return ScanIaImpactNote(headline=headline, detail=detail)

    @classmethod
    def _impact(cls, analysis: dict) -> "ScanIaBusinessImpact | None":
        """`None` quando o blob nao traz traducao de negocio nenhuma.

        Um bloco com so' a frase, ou so' as areas, e' legitimo: a tela mostra o
        que existe. O que nao pode e' um bloco vazio passando por traducao.
        """
        dados = _dict_ou_vazio(analysis.get("business_impact"))
        if not dados:
            return None

        areas: list[ScanIaImpactArea] = []
        for item in _lista_ou_vazia(dados.get("areas")):
            if not isinstance(item, dict):
                continue
            area = ScanIaImpactArea(
                area=_str_ou_none(item.get("area")),
                severity=_str_ou_none(item.get("severity")),
                title=_str_ou_none(item.get("title")),
                detail=_str_ou_none(item.get("detail")),
            )
            # Item sem texto nenhum nao e' um efeito, e' ruido do modelo.
            if area.title or area.detail:
                areas.append(area)

        headline = _str_ou_none(dados.get("headline"))
        if_fixed = cls._nota(dados.get("if_fixed_now"))
        if_deferred = cls._nota(dados.get("if_deferred"))
        regulatory = cls._nota(dados.get("regulatory"))

        if (
            headline is None
            and not areas
            and if_fixed is None
            and if_deferred is None
            and regulatory is None
        ):
            return None

        return ScanIaBusinessImpact(
            headline=headline,
            areas=areas,
            if_fixed_now=if_fixed,
            if_deferred=if_deferred,
            regulatory=regulatory,
        )

    @staticmethod
    def _deadline(analysis: dict) -> "ScanIaDeadline | None":
        """`days` sozinho ja' basta para o bloco existir: o `label` e' derivavel."""
        dados = _dict_ou_vazio(analysis.get("recommended_deadline"))
        dias = _int_ou_none(dados.get("days"))
        label = _str_ou_none(dados.get("label"))
        if dias is None and label is None:
            return None
        return ScanIaDeadline(days=dias, label=label)


class ScanToolsResponse(BaseModel):
    """Ferramentas de UMA execucao, com o status de cada uma.

    `expected` lista os ids que o pipeline executa por tier — o cliente precisa
    dele para desenhar as ferramentas de um tier que ainda nao comecou (e que
    portanto nao tem linha nenhuma em `tools`). Sem isso o front teria que
    manter sua propria copia do catalogo e as duas iriam divergir.

    `ia` acrescenta o resumo da camada de I.A do Tier 3 (attack path, CTI,
    Caldera, risco ajustado) — compacto por necessidade, ver `ScanIaSummary`.
    """

    scan_id: UUID
    commit_sha: str
    tools: list[ScanToolRunResponse]
    expected: dict[str, list[str]]
    # Resumo da camada de I.A do Tier 3. `None` quando nao existe relatorio de
    # tier 3 — o pipeline nao chegou la', ou um gate barrou antes. Vem junto de
    # `tools` porque e' a mesma pergunta ("o que aconteceu nesta execucao?") e a
    # lista de Scans ja' faz essa chamada: um endpoint novo seria um segundo
    # round-trip por card.
    ia: ScanIaSummary | None = None


class CancelScanResponse(BaseModel):
    """Desfecho de `POST /scans/{id}/cancel`.

    `tiers_cancelados` é quantas etapas estavam de fato em andamento — é o que
    diferencia "parei o pipeline inteiro" de "parei só o que faltava".
    """

    status: str
    scan_id: str
    tiers_cancelados: int
