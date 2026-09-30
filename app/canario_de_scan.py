"""Canário do pipeline de scan — NÃO MERGEAR.

Arquivo descartável, criado para disparar o pipeline num PR de verdade e
exercitar o caminho que só existe quando há PR: a entrega do patch como
GitHub **code suggestion**.

Esse caminho nunca tinha rodado de ponta a ponta. O ``SuggestPatchUseCase``
ficou órfão desde que foi escrito (nenhum worker o chamava), e quando foi
ligado, os testes saíram por scan manual — que não tem PR onde comentar. O
resultado é que o formato do que ia para o bloco ```suggestion só foi conferido
em ensaio, nunca contra o GitHub.

As duas funções abaixo têm falhas que o Semgrep pega no Tier 1, ambas com
arquivo e linha, ambas dentro de função — a indentação é parte do teste,
porque é justamente o que o modelo costuma colapsar.

Nada aqui é importado por nada. Ao terminar a verificação, feche o PR sem
merge e apague a branch.

Segunda rodada: a primeira expôs dois defeitos e os dois foram corrigidos.
O reparo de recuo rebaseava o bloco pela primeira linha, e com um `def` na
coluna 0 não corrigia nada — o corpo da função saiu com 1 espaço. Agora o
recuo é aprendido par a par, e o resultado passa por `ast.parse` antes de
sair. E findings fora do diff do PR deixaram de ser postados (levavam 422) —
viram remediação só no dashboard.
"""
from __future__ import annotations

import subprocess


def buscar_usuario_por_email(db, email: str):
    """SQL injection por interpolação — `formatted-sql-query`."""
    query = f"SELECT id, nome FROM users WHERE email = '{email}'"
    return db.execute(query).fetchall()


def contar_linhas_do_arquivo(caminho: str) -> str:
    """Command injection por shell=True — `dangerous-subprocess-use`."""
    return subprocess.check_output(f"wc -l {caminho}", shell=True).decode()
