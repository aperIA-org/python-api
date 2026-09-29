"""ZAP sob demanda no ECS Fargate (deploy AWS).

Sem ``ZAP_FARGATE_CLUSTER`` (dev, compose local) devolve a URL fixa e nada muda.
Com ele, cada scan sobe uma task, usa o IP privado dela e a derruba no fim:
parado, o ZAP não custa nada. O comando da task definition roda o ZAP sob
``timeout 3600``, então uma task órfã (worker morto no meio do scan) se encerra
sozinha.
"""
from __future__ import annotations

import time
from collections.abc import Iterator
from contextlib import contextmanager

import httpx
import structlog

from app.config import settings
from app.infrastructure.scanners.fargate_tasks import marcador_do_scan

logger = structlog.get_logger()

_BOOT_TIMEOUT_S = 300


@contextmanager
def zap_sob_demanda(url_fixa: str, commit_sha: str = "") -> Iterator[str]:
    if not settings.ZAP_FARGATE_CLUSTER:
        yield url_fixa
        return

    import boto3  # só o deploy AWS usa

    cluster = settings.ZAP_FARGATE_CLUSTER
    ecs = boto3.client("ecs", region_name=settings.AWS_REGION)
    resp = ecs.run_task(
        cluster=cluster,
        taskDefinition=settings.ZAP_FARGATE_TASK_DEF,
        launchType="FARGATE",
        # Liga a tarefa ao commit: é por aqui que o cancelamento a encontra.
        **({"startedBy": marcador_do_scan(commit_sha)} if commit_sha else {}),
        networkConfiguration={
            "awsvpcConfiguration": {
                "subnets": settings.ZAP_FARGATE_SUBNETS.split(","),
                "securityGroups": [settings.ZAP_FARGATE_SECURITY_GROUP],
                # IP público só para baixar a imagem do Docker Hub (VPC sem NAT).
                "assignPublicIp": "ENABLED",
            }
        },
        # A chave vai no override, não na task definition.
        overrides={
            "containerOverrides": [
                {
                    "name": "zap",
                    "environment": [{"name": "ZAP_API_KEY", "value": settings.ZAP_API_KEY}],
                }
            ]
        },
    )
    if not resp.get("tasks"):
        raise RuntimeError(f"Fargate não subiu o ZAP: {resp.get('failures')}")
    task_arn = resp["tasks"][0]["taskArn"]

    try:
        ecs.get_waiter("tasks_running").wait(
            cluster=cluster, tasks=[task_arn], WaiterConfig={"Delay": 10, "MaxAttempts": 60}
        )
        task = ecs.describe_tasks(cluster=cluster, tasks=[task_arn])["tasks"][0]
        ip = next(
            d["value"]
            for a in task["attachments"]
            for d in a["details"]
            if d["name"] == "privateIPv4Address"
        )
        url = f"http://{ip}:8090"
        _aguardar_zap(url)
        logger.info("zap_fargate_pronto", task=task_arn, url=url)
        yield url
    finally:
        try:
            ecs.stop_task(cluster=cluster, task=task_arn, reason="scan do aperIA terminou")
        except Exception as exc:  # noqa: BLE001 — não mascarar o erro do scan
            logger.error("zap_fargate_stop_falhou", task=task_arn, error=str(exc))


def _aguardar_zap(url: str) -> None:
    """A task fica RUNNING antes da JVM do ZAP aceitar conexões."""
    prazo = time.monotonic() + _BOOT_TIMEOUT_S
    while True:
        try:
            httpx.get(url, timeout=5)
            return
        except httpx.HTTPError:
            if time.monotonic() > prazo:
                raise TimeoutError(f"ZAP em {url} não respondeu em {_BOOT_TIMEOUT_S}s")
            time.sleep(5)
