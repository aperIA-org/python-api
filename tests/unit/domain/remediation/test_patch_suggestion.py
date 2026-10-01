"""Testes da verificação de patch — a peça que impede o bug de voltar.

O bug: o modelo devolvia um diff unificado que ia direto para um bloco
```suggestion, e "Apply suggestion" escrevia `@@`, `-` e `+` dentro do
arquivo, com a indentação colapsada. Nada disso dava erro em lugar nenhum.

Estes testes são sobre as três respostas possíveis a uma resposta do modelo:
aceitar, consertar o recuo, ou recusar.
"""
from __future__ import annotations

import pytest

from app.domain.remediation.patch_suggestion import (
    PatchInvalido,
    verificar,
)

#: Um arquivo Python de verdade — o recuo é o que está sob teste.
ARQUIVO = [
    "def upgrade():",
    "    op.create_unique_constraint(",
    '        "scan_reports_commit_tier_key", "scan_reports", ["commit_sha"]',
    "    )",
    "",
    '    op.execute(f"DROP INDEX IF EXISTS {_UQ}")',
    '    op.execute("DROP INDEX IF EXISTS idx_outro")',
]
ALVO = 6  # a linha do op.execute com f-string


def test_aceita_quando_o_eco_bate_exatamente():
    sub = verificar(
        start_line=ALVO,
        end_line=ALVO,
        original=['    op.execute(f"DROP INDEX IF EXISTS {_UQ}")'],
        replacement=['    op.execute("DROP INDEX IF EXISTS " + _UQ)'],
        linhas_do_arquivo=ARQUIVO,
    )
    assert sub.reindentado is False
    assert sub.suggestion_body() == '    op.execute("DROP INDEX IF EXISTS " + _UQ)'


def test_conserta_o_recuo_que_o_modelo_perdeu():
    """A falha real observada: 4 espaços voltaram como 1.

    O conteúdo está certo, só o recuo caiu. Como o arquivo verdadeiro está em
    mãos, dá para rebasear em vez de recusar um patch bom.
    """
    sub = verificar(
        start_line=ALVO,
        end_line=ALVO,
        original=[' op.execute(f"DROP INDEX IF EXISTS {_UQ}")'],
        replacement=[' op.execute("DROP INDEX IF EXISTS " + _UQ)'],
        linhas_do_arquivo=ARQUIVO,
    )
    assert sub.reindentado is True
    # Volta com os 4 espaços do arquivo, não com o 1 do modelo.
    assert sub.suggestion_body() == '    op.execute("DROP INDEX IF EXISTS " + _UQ)'


def test_conserta_recuo_preservando_o_relativo_do_bloco():
    """Rebasear o bloco não pode achatar o recuo interno dele."""
    sub = verificar(
        start_line=2,
        end_line=4,
        original=[
            "op.create_unique_constraint(",
            '    "scan_reports_commit_tier_key", "scan_reports", ["commit_sha"]',
            ")",
        ],
        replacement=[
            "op.create_unique_constraint(",
            '    "nova_constraint", "scan_reports", ["commit_sha", "tier"]',
            ")",
        ],
        linhas_do_arquivo=ARQUIVO,
    )
    assert sub.reindentado is True
    assert sub.replacement == [
        "    op.create_unique_constraint(",
        '        "nova_constraint", "scan_reports", ["commit_sha", "tier"]',
        "    )",
    ]


def test_recusa_quando_o_conteudo_nao_bate():
    """Âncora errada: o modelo alucinou a linha. Não há o que salvar."""
    with pytest.raises(PatchInvalido, match="nao corresponde"):
        verificar(
            start_line=ALVO,
            end_line=ALVO,
            original=["alguma outra linha que nao existe"],
            replacement=["    qualquer coisa"],
            linhas_do_arquivo=ARQUIVO,
        )


def test_recusa_intervalo_fora_do_arquivo():
    with pytest.raises(PatchInvalido, match="passa do fim"):
        verificar(
            start_line=900,
            end_line=901,
            original=["x", "y"],
            replacement=["z"],
            linhas_do_arquivo=ARQUIVO,
        )


def test_recusa_quando_o_tamanho_do_eco_diverge():
    with pytest.raises(PatchInvalido, match="original tem"):
        verificar(
            start_line=ALVO,
            end_line=ALVO,
            original=["uma", "duas"],
            replacement=["z"],
            linhas_do_arquivo=ARQUIVO,
        )


def test_recusa_replacement_vazio():
    """É como o prompt manda o modelo dizer 'não sei'."""
    with pytest.raises(PatchInvalido, match="replacement vazio"):
        verificar(
            start_line=ALVO,
            end_line=ALVO,
            original=['    op.execute(f"DROP INDEX IF EXISTS {_UQ}")'],
            replacement=[],
            linhas_do_arquivo=ARQUIVO,
        )


def test_suggestion_body_nunca_carrega_marcador_de_diff():
    """O contrato do bloco ```suggestion: linhas literais, e nada mais.

    Se um `-`, `+` ou `@@` escapar para cá, o "Apply suggestion" escreve o
    marcador dentro do arquivo do usuário. Era exatamente o bug.
    """
    sub = verificar(
        start_line=ALVO,
        end_line=ALVO,
        original=['    op.execute(f"DROP INDEX IF EXISTS {_UQ}")'],
        replacement=['    op.execute("DROP INDEX IF EXISTS " + _UQ)'],
        linhas_do_arquivo=ARQUIVO,
    )
    corpo = sub.suggestion_body()
    assert not any(l.startswith(("+", "-", "@@", "---", "+++")) for l in corpo.split("\n"))
    # E o diff de exibição é o oposto: TEM que ter os marcadores.
    diff = sub.unified_diff("alembic/versions/x.py")
    assert diff.startswith("--- a/alembic/versions/x.py")
    assert '-    op.execute(f"DROP INDEX IF EXISTS {_UQ}")' in diff
    assert '+    op.execute("DROP INDEX IF EXISTS " + _UQ)' in diff


def test_diff_de_exibicao_conta_as_linhas_certas():
    sub = verificar(
        start_line=2,
        end_line=4,
        original=ARQUIVO[1:4],
        replacement=["    op.create_unique_constraint('x', 'y', ['z'])"],
        linhas_do_arquivo=ARQUIVO,
    )
    assert "@@ -2,3 +2,1 @@" in sub.unified_diff("x.py")


def test_recusa_sugestao_que_nao_muda_nada():
    """O modelo às vezes ecoa a linha vulnerável como se fosse a correção.

    Passa em tudo — bate com o arquivo, indentação certa — e não corrige
    coisa alguma. Vira ruído no PR.
    """
    with pytest.raises(PatchInvalido, match="identico ao original"):
        verificar(
            start_line=ALVO,
            end_line=ALVO,
            original=['    op.execute(f"DROP INDEX IF EXISTS {_UQ}")'],
            replacement=['    op.execute(f"DROP INDEX IF EXISTS {_UQ}")'],
            linhas_do_arquivo=ARQUIVO,
        )


def test_recusa_no_op_disfarcado_de_recuo_perdido():
    """Mesmo caso, com o recuo colapsado — a guarda roda DEPOIS do reparo.

    Antes do reparo o texto difere e o no-op passaria despercebido.
    """
    with pytest.raises(PatchInvalido, match="identico ao original"):
        verificar(
            start_line=ALVO,
            end_line=ALVO,
            original=[' op.execute(f"DROP INDEX IF EXISTS {_UQ}")'],
            replacement=[' op.execute(f"DROP INDEX IF EXISTS {_UQ}")'],
            linhas_do_arquivo=ARQUIVO,
        )


# ------------------------------------------------- regressão do PR #20
#
# O que segue saiu de um PR de verdade. O reparo de recuo rebaseava o bloco
# pelo recuo da PRIMEIRA linha; quando ela está na coluna 0 (um `def`), a base
# é vazia dos dois lados, não há o que trocar, e o recuo interno colapsado
# passa direto. O comentário postado no PR #20 tinha o corpo da função com 1
# espaço, e "Apply suggestion" daria IndentationError.

CANARIO = [
    "import subprocess",
    "",
    "",
    "def buscar_usuario_por_email(db, email: str):",
    '    """Docstring."""',
    "    query = f\"SELECT id FROM users WHERE email = '{email}'\"",
    "    return db.execute(query).fetchall()",
]


def test_conserta_recuo_interno_quando_o_bloco_comeca_na_coluna_zero():
    """O caso exato do PR #20."""
    sub = verificar(
        start_line=4,
        end_line=7,
        # O modelo colapsou tudo para 1 espaço, menos o `def`, que já era 0.
        original=[
            "def buscar_usuario_por_email(db, email: str):",
            ' """Docstring."""',
            " query = f\"SELECT id FROM users WHERE email = '{email}'\"",
            " return db.execute(query).fetchall()",
        ],
        replacement=[
            "def buscar_usuario_por_email(db, email: str):",
            ' """Docstring."""',
            ' query = text("SELECT id FROM users WHERE email = :email")',
            ' return db.execute(query, {"email": email}).fetchall()',
        ],
        linhas_do_arquivo=CANARIO,
        file_path="app/canario_de_scan.py",
    )
    assert sub.reindentado is True
    assert sub.replacement == [
        "def buscar_usuario_por_email(db, email: str):",
        '    """Docstring."""',
        '    query = text("SELECT id FROM users WHERE email = :email")',
        '    return db.execute(query, {"email": email}).fetchall()',
    ]


def test_escala_recuo_mais_aninhado_que_o_original():
    """Código novo pode ter nível que o eco não tinha — escala pela proporção."""
    sub = verificar(
        start_line=4,
        end_line=7,
        original=[
            "def buscar_usuario_por_email(db, email: str):",
            ' """Docstring."""',
            " query = f\"SELECT id FROM users WHERE email = '{email}'\"",
            " return db.execute(query).fetchall()",
        ],
        replacement=[
            "def buscar_usuario_por_email(db, email: str):",
            " if not email:",
            "  return []",  # dois níveis do modelo → oito espaços
            " return db.execute(text(:e)).fetchall()",
        ],
        linhas_do_arquivo=CANARIO,
    )
    assert sub.replacement[2] == "        return []"


def test_recusa_quando_o_resultado_nao_compila():
    """A rede de segurança que torna a heurística de recuo aceitável."""
    with pytest.raises(PatchInvalido, match="nao compila"):
        verificar(
            start_line=6,
            end_line=6,
            original=["    query = f\"SELECT id FROM users WHERE email = '{email}'\""],
            replacement=["        query = 'quebrado'"],  # recuo inválido aqui
            linhas_do_arquivo=CANARIO,
            file_path="app/canario_de_scan.py",
        )


def test_arquivo_que_ja_nao_compilava_nao_e_culpa_do_patch():
    quebrado = ["def f(:", "    pass"]
    sub = verificar(
        start_line=2,
        end_line=2,
        original=["    pass"],
        replacement=["    return 1"],
        linhas_do_arquivo=quebrado,
        file_path="x.py",
    )
    assert sub.replacement == ["    return 1"]


def test_nao_valida_sintaxe_de_arquivo_que_nao_e_python():
    """YAML e Dockerfile passam sem `ast` — e o deploy.yml é caso real."""
    yml = ["jobs:", "  build:", "    uses: actions/checkout@v4"]
    sub = verificar(
        start_line=3,
        end_line=3,
        original=["    uses: actions/checkout@v4"],
        replacement=["    uses: actions/checkout@abc123"],
        linhas_do_arquivo=yml,
        file_path=".github/workflows/deploy.yml",
    )
    assert sub.replacement == ["    uses: actions/checkout@abc123"]


def test_recusa_recuo_com_tab():
    com_tab = ["def f():", "\tpass"]
    with pytest.raises(PatchInvalido, match="tab"):
        verificar(
            start_line=2,
            end_line=2,
            original=[" pass"],
            replacement=[" return 1"],
            linhas_do_arquivo=com_tab,
            file_path="x.py",
        )


# ------------------------------------------------- regressão do PR #21
#
# O #20 cobriu um nível de recuo. O #21 subiu para oito e doze espaços, e três
# sugestões foram recusadas com `expected an indented block after function
# definition`. A causa estava no mapa: quando o modelo achata o trecho inteiro
# na coluna 0, um mesmo recuo dele corresponde a DOIS do arquivo — o `def` a 4
# e o corpo a 8. O dicionário guardava só o último, e `def` e corpo iam para o
# mesmo nível. O `ast` pegava, mas com um erro que não apontava a causa.

CLASSE = [
    "class RepositorioDeUsuarios:",
    "    def buscar_por_email(self, email: str):",
    '        """Doc."""',
    "        query = f\"SELECT id FROM users WHERE email = '{email}'\"",
    "        return self.db.execute(query).fetchall()",
]


def test_eco_achatado_e_recusado_com_motivo_legivel():
    """O caso exato do PR #21."""
    with pytest.raises(PatchInvalido, match="eco achatado"):
        verificar(
            start_line=2,
            end_line=5,
            # Tudo na coluna 0: o `def` (4 no arquivo) e o corpo (8) viram o
            # mesmo nível, e a estrutura não tem como ser deduzida de volta.
            original=[
                "def buscar_por_email(self, email: str):",
                '"""Doc."""',
                "query = f\"SELECT id FROM users WHERE email = '{email}'\"",
                "return self.db.execute(query).fetchall()",
            ],
            replacement=[
                "def buscar_por_email(self, email: str):",
                '"""Doc."""',
                'query = text("SELECT id FROM users WHERE email = :email")',
                'return self.db.execute(query, {"email": email}).fetchall()',
            ],
            linhas_do_arquivo=CLASSE,
            file_path="app/repo.py",
        )


def test_eco_com_um_nivel_preservado_ainda_funciona():
    """Basta o modelo manter UM espaço de diferença para o mapa fechar."""
    sub = verificar(
        start_line=2,
        end_line=5,
        original=[
            "def buscar_por_email(self, email: str):",
            ' """Doc."""',
            " query = f\"SELECT id FROM users WHERE email = '{email}'\"",
            " return self.db.execute(query).fetchall()",
        ],
        replacement=[
            "def buscar_por_email(self, email: str):",
            ' """Doc."""',
            ' query = text("SELECT id FROM users WHERE email = :email")',
            ' return self.db.execute(query, {"email": email}).fetchall()',
        ],
        linhas_do_arquivo=CLASSE,
        file_path="app/repo.py",
    )
    assert sub.replacement[0] == "    def buscar_por_email(self, email: str):"
    assert sub.replacement[2].startswith("        query = text(")


def test_uma_linha_a_doze_espacos_e_o_caminho_que_sempre_funciona():
    """Trecho de uma linha não tem ambiguidade — e o PR #21 confirmou.

    As três recusas de lá eram multilinha atravessando a assinatura; as
    substituições de uma linha só passaram todas, inclusive a 12 espaços.
    O prompt agora proíbe incluir a linha de `def` por causa disso.
    """
    arquivo = CLASSE + ["", "    def exportar(self, destino: str) -> None:", "        try:", "            run(cmd, shell=True)"]
    sub = verificar(
        start_line=9,
        end_line=9,
        original=["run(cmd, shell=True)"],
        replacement=["run(cmd, shell=False)"],
        linhas_do_arquivo=arquivo,
    )
    assert sub.replacement == ["            run(cmd, shell=False)"]
