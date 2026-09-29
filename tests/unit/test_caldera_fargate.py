"""Caldera sob demanda: sem cluster não toca na AWS; com cluster, nada fica de pé.

Endpoint de VPC é cobrado por hora — um `finally` que não limpasse viraria
custo silencioso, então é isso que estes testes prendem.
"""
import sys
import types

import pytest

from app.infrastructure.scanners import caldera_fargate
from app.presentation.workers import tier3_scan_worker


class _FakeEc2:
    def __init__(self, orfaos=()):
        self.criados = []
        self.apagados = []
        self._orfaos = list(orfaos)

    def create_vpc_endpoint(self, **kw):
        eid = f"vpce-{len(self.criados)}"
        self.criados.append(eid)
        return {"VpcEndpoint": {"VpcEndpointId": eid}}

    def describe_vpc_endpoints(self, **kw):
        if "Filters" in kw:
            return {"VpcEndpoints": [{"VpcEndpointId": e, "State": "available"} for e in self._orfaos]}
        return {"VpcEndpoints": [{"VpcEndpointId": e, "State": "available"} for e in kw["VpcEndpointIds"]]}

    def delete_vpc_endpoints(self, **kw):
        self.apagados.extend(kw["VpcEndpointIds"])


class _FakeEcs:
    def __init__(self):
        self.stopped = []

    def run_task(self, **kw):
        return {"tasks": [{"taskArn": "arn:task/1"}], "failures": []}

    def get_waiter(self, name):
        return types.SimpleNamespace(wait=lambda **kw: None)

    def describe_tasks(self, **kw):
        return {"tasks": [{"attachments": [{"details": [
            {"name": "privateIPv4Address", "value": "172.31.128.9"}]}]}]}

    def stop_task(self, **kw):
        self.stopped.append(kw["task"])


@pytest.fixture
def aws(monkeypatch):
    ec2, ecs = _FakeEc2(orfaos=["vpce-orfao"]), _FakeEcs()
    monkeypatch.setattr(caldera_fargate.settings, "CALDERA_FARGATE_CLUSTER", "aperia")
    monkeypatch.setattr(caldera_fargate.settings, "CALDERA_FARGATE_SUBNET", "subnet-1")
    clientes = {"ec2": ec2, "ecs": ecs}
    monkeypatch.setitem(
        sys.modules, "boto3", types.SimpleNamespace(client=lambda nome, **k: clientes[nome])
    )
    monkeypatch.setattr(caldera_fargate, "_aguardar_caldera", lambda url: None)
    return ec2, ecs


def test_sem_cluster_usa_url_fixa(monkeypatch):
    monkeypatch.setattr(caldera_fargate.settings, "CALDERA_FARGATE_CLUSTER", "")
    with caldera_fargate.caldera_sob_demanda("http://caldera:8888") as url:
        assert url == "http://caldera:8888"


def test_para_task_e_apaga_endpoints_mesmo_se_a_operacao_falhar(aws):
    ec2, ecs = aws
    with pytest.raises(RuntimeError, match="operação quebrou"):
        with caldera_fargate.caldera_sob_demanda("http://caldera:8888") as url:
            assert url == "http://172.31.128.9:8888"
            raise RuntimeError("operação quebrou")

    assert ecs.stopped == ["arn:task/1"]
    # Os 3 efêmeros desta execução, mais o órfão que a varredura inicial achou.
    assert set(ec2.criados) <= set(ec2.apagados)
    assert "vpce-orfao" in ec2.apagados


def test_fargate_fora_do_ar_nao_derruba_o_tier3(monkeypatch):
    """O `with` fica fora do `run_safe`, então precisa do seu próprio isolamento."""
    monkeypatch.setattr(
        tier3_scan_worker,
        "caldera_sob_demanda",
        lambda url, commit_sha="": (_ for _ in ()).throw(RuntimeError("ECS fora do ar")),
    )
    monkeypatch.setattr(tier3_scan_worker, "ThreatIntelClient", lambda: None)
    monkeypatch.setattr(tier3_scan_worker, "persistir_ou_falhar", lambda *a, **k: None)
    monkeypatch.setattr(
        tier3_scan_worker.scan_tool_run_writer, "record_tool_run", lambda **k: None
    )

    out = tier3_scan_worker.run_tier3_scan.run(
        target_url=None, t2_findings=[], commit_sha="abc123", repo_url="http://x"
    )

    assert out["caldera_results"]["status"] == "failed"
    assert out["caldera_results"]["reason"] == "RuntimeError"
    assert out["caldera_results"]["caldera_validated"] is False


def test_espera_o_agente_registrar_nao_so_o_servidor(monkeypatch):
    """Servidor de pé com zero agentes é uma operação sem alvo — não serve."""
    import httpx

    monkeypatch.setattr(caldera_fargate.settings, "CALDERA_AGENT_GROUP", "red")
    respostas = [[], [], [{"group": "red", "paw": "aperia-sandbox"}]]
    chamadas = []

    class _Cliente:
        def __init__(self, **kw):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def get(self, path):
            chamadas.append(path)
            return httpx.Response(
                200, json=respostas[len(chamadas) - 1], request=httpx.Request("GET", path)
            )

    monkeypatch.setattr(caldera_fargate.httpx, "Client", _Cliente)
    monkeypatch.setattr(caldera_fargate.time, "sleep", lambda s: None)

    caldera_fargate._aguardar_caldera("http://10.0.0.1:8888")

    assert len(chamadas) == 3  # só voltou quando o agente apareceu


def test_agente_que_nunca_registra_estoura_prazo(monkeypatch):
    import httpx

    class _Cliente:
        def __init__(self, **kw):
            pass

        def __enter__(self):
            return self

        def __exit__(self, *a):
            return False

        def get(self, path):
            return httpx.Response(200, json=[], request=httpx.Request("GET", path))

    monkeypatch.setattr(caldera_fargate.httpx, "Client", _Cliente)
    monkeypatch.setattr(caldera_fargate.time, "sleep", lambda s: None)
    monkeypatch.setattr(caldera_fargate, "_BOOT_TIMEOUT_S", 0)

    with pytest.raises(TimeoutError, match="nenhum agente"):
        caldera_fargate._aguardar_caldera("http://10.0.0.1:8888")
