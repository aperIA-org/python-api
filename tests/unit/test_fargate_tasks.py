"""Encerrar as tarefas de um scan: achar as certas, e nunca derrubar o cancelamento."""
import sys
import types

from app.infrastructure.scanners import fargate_tasks
from app.infrastructure.scanners.fargate_tasks import (
    marcador_do_scan,
    parar_tarefas_do_scan,
)


def test_marcador_cabe_no_limite_do_ecs():
    """`startedBy` aceita 36 caracteres; um sha inteiro não caberia."""
    assert len(marcador_do_scan("08736bdbacbc536564831606efd03df32130ba19")) <= 36


def test_marcador_e_estavel_entre_processos():
    """Quem cria a tarefa e quem a encerra são processos diferentes."""
    sha = "08736bdbacbc536564831606efd03df32130ba19"
    assert marcador_do_scan(sha) == marcador_do_scan(sha)


class _EcsFake:
    def __init__(self, arns):
        self._arns = arns
        self.paradas = []
        self.filtro = None

    def list_tasks(self, **kw):
        self.filtro = kw
        return {"taskArns": self._arns}

    def stop_task(self, **kw):
        self.paradas.append(kw["task"])


def _com_ecs(monkeypatch, ecs):
    monkeypatch.setattr(fargate_tasks.settings, "ZAP_FARGATE_CLUSTER", "aperia")
    monkeypatch.setitem(
        sys.modules, "boto3", types.SimpleNamespace(client=lambda *a, **k: ecs)
    )


def test_para_apenas_as_tarefas_daquele_commit(monkeypatch):
    """Buscar por família alcançaria a tarefa de outro scan em paralelo."""
    ecs = _EcsFake(["arn:task/1", "arn:task/2"])
    _com_ecs(monkeypatch, ecs)

    assert parar_tarefas_do_scan("abc123def456ghi789") == 2
    assert ecs.paradas == ["arn:task/1", "arn:task/2"]
    assert ecs.filtro["startedBy"] == marcador_do_scan("abc123def456ghi789")
    assert ecs.filtro["desiredStatus"] == "RUNNING"


def test_sem_cluster_configurado_nao_tenta_nada(monkeypatch):
    monkeypatch.setattr(fargate_tasks.settings, "ZAP_FARGATE_CLUSTER", "")
    monkeypatch.setattr(fargate_tasks.settings, "CALDERA_FARGATE_CLUSTER", "")
    assert parar_tarefas_do_scan("abc123") == 0


def test_ecs_fora_do_ar_nao_derruba_o_cancelamento(monkeypatch):
    """O cancelamento do pipeline já aconteceu; o `timer` cobre o resto."""
    class _Quebrado:
        def list_tasks(self, **kw):
            raise RuntimeError("ECS fora do ar")

    _com_ecs(monkeypatch, _Quebrado())
    assert parar_tarefas_do_scan("abc123") == 0


class _EcsComTarefas:
    def __init__(self, tarefas):
        self._tarefas = tarefas
        self.paradas = []

    def list_tasks(self, **kw):
        return {"taskArns": [t["taskArn"] for t in self._tarefas]}

    def describe_tasks(self, **kw):
        return {"tasks": self._tarefas}

    def stop_task(self, **kw):
        self.paradas.append(kw["task"])


def test_varredura_poupa_tarefa_de_scan_ainda_ativo(monkeypatch):
    """Parar a tarefa de um scan vivo abortaria o scan de outra pessoa."""
    viva = marcador_do_scan("aaaa111122223333")
    morta = marcador_do_scan("bbbb444455556666")
    ecs = _EcsComTarefas([
        {"taskArn": "arn:viva", "startedBy": viva},
        {"taskArn": "arn:morta", "startedBy": morta},
    ])
    _com_ecs(monkeypatch, ecs)

    paradas = fargate_tasks.parar_tarefas_orfas({viva})

    assert ecs.paradas == ["arn:morta"]
    assert paradas == [morta]


def test_varredura_ignora_tarefa_sem_marcador(monkeypatch):
    """Sem marcador não dá para saber de quem é — derrubar às cegas é pior."""
    ecs = _EcsComTarefas([
        {"taskArn": "arn:antiga", "startedBy": None},
        {"taskArn": "arn:outra", "startedBy": "algo-de-fora"},
    ])
    _com_ecs(monkeypatch, ecs)

    assert fargate_tasks.parar_tarefas_orfas(set()) == []
    assert ecs.paradas == []
