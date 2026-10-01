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
    """EC2 de mentira que modela o CICLO DE VIDA do endpoint, não só a chamada.

    `delete_vpc_endpoints` na AWS é assíncrono: o endpoint passa por
    `deleting` antes de sumir, e nesse intervalo ainda segura o DNS privado.
    Um fake que apagasse na hora esconderia exatamente o bug que derrubou a
    emulação em produção — e um que nunca apagasse faria o teste esperar o
    prazo inteiro.

    `ciclos_ate_sumir` é quantas leituras o endpoint sobrevive em `deleting`.
    """

    def __init__(self, orfaos=(), ciclos_ate_sumir=0):
        self.criados = []
        self.apagados = []
        self.ciclos_ate_sumir = ciclos_ate_sumir
        # id -> [estado, leituras restantes em deleting]
        self._efemeros = {e: ["available", 0] for e in orfaos}

    def create_vpc_endpoint(self, **kw):
        eid = f"vpce-{len(self.criados)}"
        self.criados.append(eid)
        self._efemeros[eid] = ["available", 0]
        return {"VpcEndpoint": {"VpcEndpointId": eid}}

    def _linhas(self, ids):
        saida = []
        for eid in ids:
            estado, restantes = self._efemeros[eid]
            saida.append({"VpcEndpointId": eid, "State": estado})
            if estado == "deleting":
                if restantes <= 0:
                    self._efemeros[eid][0] = "deleted"
                else:
                    self._efemeros[eid][1] -= 1
        return saida

    def describe_vpc_endpoints(self, **kw):
        alvos = (
            [e for e, (estado, _) in self._efemeros.items() if estado != "deleted"]
            if "Filters" in kw
            else kw["VpcEndpointIds"]
        )
        return {"VpcEndpoints": self._linhas(alvos)}

    def delete_vpc_endpoints(self, **kw):
        self.apagados.extend(kw["VpcEndpointIds"])
        for eid in kw["VpcEndpointIds"]:
            self._efemeros[eid] = ["deleting", self.ciclos_ate_sumir]


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


# ── Corrida de DNS entre dois scans em Tier 3 ───────────────────────────────
#
# Em produção, dois scans seguidos derrubaram a emulação: o `finally` do
# primeiro pediu a exclusão dos endpoints (chamada assíncrona) e o segundo
# tentou criar os seus um segundo depois. O endpoint em `deleting` ainda era
# dono de `api.ecr.<região>.amazonaws.com`, e a criação com
# `PrivateDnsEnabled=True` falhou com `InvalidParameter`.


def test_espera_o_endpoint_em_deleting_sumir_antes_de_criar(monkeypatch):
    """O caso exato da produção: o órfão já está em `deleting` ao chegarmos.

    A versão antiga ignorava `deleting` ("não há o que apagar") e seguia
    direto para a criação — que batia no DNS ainda registrado.
    """
    ec2 = _FakeEc2(ciclos_ate_sumir=2)
    ec2._efemeros["vpce-saindo"] = ["deleting", 2]
    monkeypatch.setattr(caldera_fargate.time, "sleep", lambda s: None)

    caldera_fargate._apagar_endpoints_orfaos(ec2)

    # Não pede exclusão de novo — já estava indo embora.
    assert ec2.apagados == []
    # Mas só retorna quando o endpoint realmente sumiu.
    assert caldera_fargate._efemeros_vivos(ec2) == {}


def test_apaga_o_orfao_e_so_volta_quando_ele_some(monkeypatch):
    ec2 = _FakeEc2(orfaos=["vpce-orfao"], ciclos_ate_sumir=3)
    monkeypatch.setattr(caldera_fargate.time, "sleep", lambda s: None)

    caldera_fargate._apagar_endpoints_orfaos(ec2)

    assert ec2.apagados == ["vpce-orfao"]
    assert caldera_fargate._efemeros_vivos(ec2) == {}


def test_sem_efemeros_nao_espera_nada(monkeypatch):
    """O caminho comum: nada pendente, a criação começa na hora."""
    ec2 = _FakeEc2()
    dormiu = []
    monkeypatch.setattr(caldera_fargate.time, "sleep", lambda s: dormiu.append(s))

    caldera_fargate._apagar_endpoints_orfaos(ec2)

    assert dormiu == []
    assert ec2.apagados == []


def test_prazo_estourado_segue_em_frente_em_vez_de_levantar(monkeypatch):
    """Travar aqui seria pior: o caminho de Caldera indisponível já existe.

    A criação a seguir falha com o ClientError de sempre e o Tier 3 continua
    sem emulação — o que este ramo acrescenta é o log que explica a causa.
    """
    ec2 = _FakeEc2(orfaos=["vpce-teimoso"], ciclos_ate_sumir=10**6)
    monkeypatch.setattr(caldera_fargate.time, "sleep", lambda s: None)
    monkeypatch.setattr(caldera_fargate, "_PRAZO_EXCLUSAO_ENDPOINT", 0)

    caldera_fargate._apagar_endpoints_orfaos(ec2)  # não levanta

    assert caldera_fargate._efemeros_vivos(ec2) != {}


def test_deleted_nao_conta_como_vivo():
    """`deleted` já liberou o DNS; só `deleting` ainda segura."""
    ec2 = _FakeEc2()
    ec2._efemeros = {
        "vpce-foi": ["deleted", 0],
        "vpce-saindo": ["deleting", 5],
        "vpce-ativo": ["available", 0],
    }
    assert caldera_fargate._efemeros_vivos(ec2) == {
        "vpce-saindo": "deleting",
        "vpce-ativo": "available",
    }
