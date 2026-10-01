"""Canário de recuo aninhado — NÃO MERGEAR.

O canário anterior (PR #20) cobriu dois níveis: função no topo do módulo e
corpo com 4 espaços. Faltou o caso que estressa de verdade o reparo de recuo —
código a 8 e 12 espaços, dentro de método e de bloco condicional.

Importa porque o reparo APRENDE a correspondência de recuo emparelhando o eco
do modelo com as linhas reais, e escala por proporção os níveis que o eco não
tinha. Com um só nível, aprender e escalar dão no mesmo; é a partir do segundo
que eles divergem, e é aí que um erro vira `IndentationError`.

Nada aqui é importado por nada. Fechar o PR sem merge ao terminar.

Segunda rodada. A primeira recusou as três correções de SQL dentro da classe
com `expected an indented block`, e a causa estava no mapa de recuo: quando o
modelo achata o trecho na coluna 0, o `def` (4 no arquivo) e o corpo (8) viram
o mesmo nível, e o dicionário guardava só o último. Agora o conflito é
detectado e recusado com motivo legível — e o prompt passou a proibir incluir
a linha de assinatura, porque substituição de UMA linha passou em 100% dos
casos e multilinha atravessando o `def` falhou em 100%.
"""
from __future__ import annotations

import subprocess


class RepositorioDeUsuarios:
    """Métodos a 4 espaços, corpo a 8, bloco interno a 12."""

    def __init__(self, db) -> None:
        self.db = db

    def buscar_por_email(self, email: str):
        """SQL injection a 8 espaços de recuo."""
        query = f"SELECT id, nome FROM users WHERE email = '{email}'"
        return self.db.execute(query).fetchall()

    def contar_por_dominio(self, dominio: str, incluir_inativos: bool):
        """SQL injection a 12 espaços, dentro de condicional."""
        if incluir_inativos:
            query = f"SELECT COUNT(*) FROM users WHERE email LIKE '%@{dominio}'"
        else:
            query = (
                f"SELECT COUNT(*) FROM users WHERE email LIKE '%@{dominio}' "
                "AND ativo = true"
            )
        return self.db.execute(query).scalar()

    def exportar_para_arquivo(self, destino: str) -> None:
        """Command injection a 12 espaços, dentro de try."""
        try:
            subprocess.run(f"pg_dump users > {destino}", shell=True, check=True)
        except subprocess.CalledProcessError:
            raise
