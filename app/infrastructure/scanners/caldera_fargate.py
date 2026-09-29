"""Caldera sob demanda no ECS Fargate (deploy AWS).

Sem ``CALDERA_FARGATE_CLUSTER`` (dev, compose local) devolve a URL fixa e nada
muda. Com ele, cada scan sobe uma task com o servidor e o agente sandcat e a
derruba no fim.

ISOLAMENTO — o mesmo contrato do ``internal: true`` do docker-compose.scanners.yml,
traduzido para a VPC. A task roda numa subnet cuja route table só tem a rota
local (nenhum internet gateway), sem IP público e sem task role, e o security
group só deixa sair 443 para os endpoints da VPC. O agente executa técnicas
MITRE ATT&CK reais: é esse cerco que impede que movimento lateral de teste
alcance a internet, o RDS ou a EC2 da API. Não afrouxe nenhuma das três peças
(route table, security group, ausência de task role) — elas só valem juntas.

Sem rota para a internet a imagem não vem do Docker Hub: ela fica num ECR
privado, alcançado por endpoints de interface. Endpoint parado custa por hora,
então eles nascem e morrem com a task — ~US$0,03/h contra ~US$23/mês ligados.
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

_BOOT_TIMEOUT_S = 600
#: Serviços que o pull da imagem (ECR) e os logs exigem dentro da subnet sem saída.
_SERVICOS = ("ecr.api", "ecr.dkr", "logs")
_TAG_EFEMERO = [{"Key": "project", "Value": "aperia"}, {"Key": "efemero", "Value": "true"}]


@contextmanager
def caldera_sob_demanda(url_fixa: str, commit_sha: str = "") -> Iterator[str]:
    if not settings.CALDERA_FARGATE_CLUSTER:
        yield url_fixa
        return

    import boto3  # só o deploy AWS usa

    ec2 = boto3.client("ec2", region_name=settings.AWS_REGION)
    ecs = boto3.client("ecs", region_name=settings.AWS_REGION)
    cluster = settings.CALDERA_FARGATE_CLUSTER
    subnet = settings.CALDERA_FARGATE_SUBNET

    _apagar_endpoints_orfaos(ec2)
    endpoints = _criar_endpoints(ec2, subnet)
    task_arn = None
    try:
        resp = ecs.run_task(
            cluster=cluster,
            taskDefinition=settings.CALDERA_FARGATE_TASK_DEF,
            launchType="FARGATE",
            # Liga a tarefa ao commit: é por aqui que o cancelamento a encontra.
            **({"startedBy": marcador_do_scan(commit_sha)} if commit_sha else {}),
            networkConfiguration={
                "awsvpcConfiguration": {
                    "subnets": [subnet],
                    "securityGroups": [settings.CALDERA_FARGATE_SECURITY_GROUP],
                    "assignPublicIp": "DISABLED",
                }
            },
        )
        if not resp.get("tasks"):
            raise RuntimeError(f"Fargate não subiu o Caldera: {resp.get('failures')}")
        task_arn = resp["tasks"][0]["taskArn"]

        ecs.get_waiter("tasks_running").wait(
            cluster=cluster, tasks=[task_arn], WaiterConfig={"Delay": 15, "MaxAttempts": 40}
        )
        task = ecs.describe_tasks(cluster=cluster, tasks=[task_arn])["tasks"][0]
        ip = next(
            d["value"]
            for a in task["attachments"]
            for d in a["details"]
            if d["name"] == "privateIPv4Address"
        )
        url = f"http://{ip}:8888"
        _aguardar_caldera(url)
        logger.info("caldera_fargate_pronto", task=task_arn, url=url)
        yield url
    finally:
        # Cada limpeza no seu try: um endpoint órfão custa por hora, então a
        # falha ao parar a task não pode impedir que eles sejam apagados.
        if task_arn:
            try:
                ecs.stop_task(cluster=cluster, task=task_arn, reason="scan do aperIA terminou")
            except Exception as exc:  # noqa: BLE001 — não mascarar o erro do scan
                logger.error("caldera_fargate_stop_falhou", task=task_arn, error=str(exc))
        try:
            ec2.delete_vpc_endpoints(VpcEndpointIds=endpoints)
        except Exception as exc:  # noqa: BLE001
            logger.error("caldera_endpoints_nao_apagados", endpoints=endpoints, error=str(exc))


def _criar_endpoints(ec2, subnet: str) -> list[str]:
    ids = []
    for servico in _SERVICOS:
        ids.append(
            ec2.create_vpc_endpoint(
                VpcId=settings.CALDERA_FARGATE_VPC,
                ServiceName=f"com.amazonaws.{settings.AWS_REGION}.{servico}",
                VpcEndpointType="Interface",
                SubnetIds=[subnet],
                SecurityGroupIds=[settings.CALDERA_FARGATE_VPCE_SECURITY_GROUP],
                PrivateDnsEnabled=True,
                TagSpecifications=[{"ResourceType": "vpc-endpoint", "Tags": _TAG_EFEMERO}],
            )["VpcEndpoint"]["VpcEndpointId"]
        )
    prazo = time.monotonic() + 300
    while True:
        estados = {
            e["VpcEndpointId"]: e["State"]
            for e in ec2.describe_vpc_endpoints(VpcEndpointIds=ids)["VpcEndpoints"]
        }
        if all(v == "available" for v in estados.values()):
            return ids
        if time.monotonic() > prazo:
            ec2.delete_vpc_endpoints(VpcEndpointIds=ids)
            raise TimeoutError(f"endpoints da VPC não ficaram prontos: {estados}")
        time.sleep(10)


def _apagar_endpoints_orfaos(ec2) -> None:
    """Rede de segurança: um ``finally`` que não rodou deixaria custo por hora."""
    orfaos = [
        e["VpcEndpointId"]
        for e in ec2.describe_vpc_endpoints(
            Filters=[{"Name": "tag:efemero", "Values": ["true"]}]
        )["VpcEndpoints"]
        if e["State"] not in ("deleting", "deleted")
    ]
    if orfaos:
        logger.warning("caldera_endpoints_orfaos_removidos", endpoints=orfaos)
        ec2.delete_vpc_endpoints(VpcEndpointIds=orfaos)


def _aguardar_caldera(url: str) -> None:
    """Espera o servidor responder **e** o agente registrar.

    Esperar só o HTTP não basta: o sandcat é compilado sob demanda no primeiro
    download, então o agente aparece bem depois do servidor. Devolver a URL
    antes disso faz a operação rodar sem alvo, e aí `techniques_executed=0`
    com `caldera_validated=False` se confunde com "emulação não achou nada" —
    o mesmo engano que o `-paw` fixo do compose evita do outro lado. Estourar
    o prazo vira `failed` com motivo próprio, que é distinguível.
    """
    prazo = time.monotonic() + _BOOT_TIMEOUT_S
    grupo = settings.CALDERA_AGENT_GROUP
    cliente = httpx.Client(base_url=url, headers={"KEY": settings.CALDERA_API_KEY}, timeout=10)
    with cliente:
        while True:
            agentes = 0
            try:
                resp = cliente.get("/api/v2/agents")
                resp.raise_for_status()
                agentes = sum(1 for a in resp.json() if a.get("group") == grupo)
                if agentes:
                    return
            except (httpx.HTTPError, ValueError):
                pass
            if time.monotonic() > prazo:
                raise TimeoutError(
                    f"Caldera em {url}: nenhum agente no grupo {grupo} "
                    f"em {_BOOT_TIMEOUT_S}s (agentes vistos: {agentes})"
                )
            time.sleep(10)
