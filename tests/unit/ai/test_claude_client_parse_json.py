"""Testes do parser de JSON das respostas do Claude.

Os prompts pedem JSON estrito sem fences. O modelo quase sempre obedece — e
"quase" derrubava a remediação de um finding inteiro quando ele resolvia
acrescentar uma frase no fim, com um erro (`Extra data: line 14 column 1`)
que não dizia nada a quem lia o log.
"""
from __future__ import annotations

import pytest

from app.infrastructure.ai.claude_client import ClaudeClient, ClaudeClientError

FENCE = "```"


@pytest.mark.parametrize(
    "texto",
    [
        '{"a": 1}',
        f'{FENCE}json\n{{"a": 1}}\n{FENCE}',
        f'{FENCE}\n{{"a": 1}}\n{FENCE}',
        '{"a": 1}\n\nEspero que ajude!',
        f'{FENCE}json\n{{"a": 1}}\n{FENCE}\n\nQualquer coisa é só falar.',
        'Claro, segue:\n{"a": 1}',
        '  \n {"a": 1} \n ',
    ],
)
def test_extrai_o_objeto_seja_qual_for_o_embrulho(texto):
    assert ClaudeClient._parse_json(texto) == {"a": 1}


def test_preserva_conteudo_aninhado_e_acentos():
    bruto = f'{FENCE}json\n{{"linhas": ["    op.execute(x)", ""], "nota": "ação"}}\n{FENCE}'
    assert ClaudeClient._parse_json(bruto) == {
        "linhas": ["    op.execute(x)", ""],
        "nota": "ação",
    }


def test_recusa_o_que_nao_e_objeto():
    """Uma lista no topo não serve: todo chamador faz `.get(...)`."""
    with pytest.raises(ClaudeClientError, match="não é um objeto"):
        ClaudeClient._parse_json('[1, 2, 3]')


def test_recusa_lixo():
    with pytest.raises(ClaudeClientError, match="não é JSON válido"):
        ClaudeClient._parse_json("desculpe, não consegui")
