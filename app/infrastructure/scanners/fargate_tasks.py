"""Liga as tarefas Fargate de um scan ao commit que as pediu.

Sem esse vínculo não havia como encerrá-las ao cancelar: o ECS lista tarefas do
cluster, não tarefas "daquele scan". O ``startedBy`` do ``run_task`` existe
exatamente para isso — é um rótulo de origem que o ``list_tasks`` filtra.

Por que não uma tag: ``list_tasks`` não filtra por tag, só por ``startedBy``,
``family`` ou ``service``. Buscar por família encontraria também a tarefa de
**outro** scan rodando em paralelo, e cancelar um derrubaria o outro.
"""
from __future__ import annotations

import structlog

from app.config import settings

logger = structlog.get_logger()

#: O ECS limita `startedBy` a 36 caracteres; o prefixo mais meio sha cabem.
_PREFIXO = "aperia-"


def marcador_do_scan(commit_sha: str) -> str:
    """Identifica as tarefas de um commit. Estável entre processos."""
    return f"{_PREFIXO}{commit_sha[:16]}"


def parar_tarefas_do_scan(commit_sha: str) -> int:
    """Encerra as tarefas Fargate ainda de pé para este commit.

    Chamado no cancelamento. Sem isso, a emulação e o teste dinâmico seguiriam
    rodando depois de o usuário mandar parar — o container ``timer`` da tarefa
    acabaria encerrando em até uma hora, mas até lá ela continua consumindo, e
    quem cancelou não tem por que pagar essa espera.

    Best-effort de propósito: o cancelamento do pipeline já aconteceu quando
    isto roda, e falhar aqui não pode desfazê-lo. O ``timer`` continua sendo a
    rede de segurança.
    """
    cluster = settings.ZAP_FARGATE_CLUSTER or settings.CALDERA_FARGATE_CLUSTER
    if not cluster:
        return 0

    try:
        import boto3

        ecs = boto3.client("ecs", region_name=settings.AWS_REGION)
        arns = ecs.list_tasks(
            cluster=cluster,
            startedBy=marcador_do_scan(commit_sha),
            desiredStatus="RUNNING",
        ).get("taskArns", [])

        for arn in arns:
            ecs.stop_task(cluster=cluster, task=arn, reason="scan cancelado pelo usuario")

        if arns:
            logger.info(
                "fargate_tarefas_encerradas", commit_sha=commit_sha, total=len(arns)
            )
        return len(arns)
    except Exception as exc:  # noqa: BLE001 — best-effort, o timer cobre
        logger.warning(
            "fargate_parada_falhou", commit_sha=commit_sha, error=str(exc)
        )
        return 0


def parar_tarefas_orfas(marcadores_ativos: set[str]) -> list[str]:
    """Encerra tarefas cujo scan não existe mais. Devolve os marcadores parados.

    O caso que motivou isto: um deploy recria o container do worker, e a tarefa
    Celery que estava no Tier 3 morre sem rodar o ``finally`` que derruba o
    Fargate. A tarefa fica de pé consumindo até o teto de uma hora do próprio
    container — e, pior, parece que o cancelamento não funcionou.

    Conservador de propósito: só para o que tem marcador **e** cujo scan já não
    está em andamento. Tarefa sem marcador é de antes desta versão e fica para
    o teto; derrubá-la às cegas arriscaria matar o scan de outra pessoa.
    """
    cluster = settings.ZAP_FARGATE_CLUSTER or settings.CALDERA_FARGATE_CLUSTER
    if not cluster:
        return []

    paradas: list[str] = []
    try:
        import boto3

        ecs = boto3.client("ecs", region_name=settings.AWS_REGION)
        arns = ecs.list_tasks(cluster=cluster, desiredStatus="RUNNING").get("taskArns", [])
        if not arns:
            return []

        for tarefa in ecs.describe_tasks(cluster=cluster, tasks=arns).get("tasks", []):
            marcador = tarefa.get("startedBy") or ""
            if not marcador.startswith(_PREFIXO) or marcador in marcadores_ativos:
                continue
            ecs.stop_task(
                cluster=cluster,
                task=tarefa["taskArn"],
                reason="scan encerrado; tarefa orfa",
            )
            paradas.append(marcador)
    except Exception as exc:  # noqa: BLE001 — best-effort, nunca impede o boot
        logger.warning("fargate_varredura_orfas_falhou", error=str(exc))

    return paradas
