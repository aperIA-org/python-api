"""ZAP sob demanda: sem cluster não toca na AWS; com cluster, a task sempre para."""
import sys
import types

import pytest

from app.infrastructure.scanners import zap_fargate


class _FakeEcs:
    def __init__(self):
        self.stopped = []

    def run_task(self, **kw):
        return {"tasks": [{"taskArn": "arn:task/1"}], "failures": []}

    def get_waiter(self, name):
        return types.SimpleNamespace(wait=lambda **kw: None)

    def describe_tasks(self, **kw):
        return {"tasks": [{"attachments": [{"details": [
            {"name": "privateIPv4Address", "value": "10.0.0.5"}]}]}]}

    def stop_task(self, **kw):
        self.stopped.append(kw["task"])


def test_sem_cluster_usa_url_fixa(monkeypatch):
    monkeypatch.setattr(zap_fargate.settings, "ZAP_FARGATE_CLUSTER", "")
    with zap_fargate.zap_sob_demanda("http://zap:8090") as url:
        assert url == "http://zap:8090"


def test_com_cluster_para_a_task_mesmo_se_o_scan_falhar(monkeypatch):
    ecs = _FakeEcs()
    monkeypatch.setattr(zap_fargate.settings, "ZAP_FARGATE_CLUSTER", "aperia")
    monkeypatch.setitem(sys.modules, "boto3", types.SimpleNamespace(client=lambda *a, **k: ecs))
    monkeypatch.setattr(zap_fargate, "_aguardar_zap", lambda url: None)

    with pytest.raises(RuntimeError, match="scan quebrou"):
        with zap_fargate.zap_sob_demanda("http://zap:8090") as url:
            assert url == "http://10.0.0.5:8090"
            raise RuntimeError("scan quebrou")

    assert ecs.stopped == ["arn:task/1"]
