"""Canário do primeiro scan em produção — NÃO MERGEAR.

Os canários anteriores (#20 e #21) rodaram contra o stack local, com o webhook
desviado por ngrok. Este é o primeiro a atravessar o caminho real: GitHub →
EC2 → Celery → Claude → suggestion de volta no PR.

O que ele não repete de propósito: os casos que já foram medidos. Sobra o que
ainda não foi exercitado em produção — se os workers do deploy novo pegam a
task `suggest_remediations`, se a fila `reporting` a consome, e se o patch
chega ao PR com o mesmo formato que chegava localmente.

Duas falhas de uma linha cada, do tipo que passou em 100% das rodadas
anteriores. Se ALGO sair errado aqui, é do ambiente, não do formato — e é
isso que este canário vem medir.

Nada aqui é importado por nada. Fechar o PR sem merge ao terminar.
"""
from __future__ import annotations

import subprocess


def buscar_por_dominio(db, dominio: str):
    """SQL injection por interpolação — `formatted-sql-query`."""
    sql = f"SELECT id, email FROM users WHERE email LIKE '%@{dominio}'"
    return db.execute(sql).fetchall()


def compactar_logs(caminho: str) -> bytes:
    """Command injection por shell=True — `dangerous-subprocess-use`."""
    return subprocess.check_output(f"tar czf - {caminho}", shell=True)
