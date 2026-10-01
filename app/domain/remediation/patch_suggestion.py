"""Transforma a resposta do modelo numa substituição verificada.

O modelo devolve um trecho novo (`replacement`) mais o eco do trecho que ele
acha que está trocando (`original`). Nada disso é confiável sozinho: a versão
anterior deste fluxo entregava direto ao GitHub o que o modelo escreveu, e o
resultado era um bloco ```` ```suggestion ```` contendo marcadores de diff e
indentação errada — "Apply suggestion" quebrava o arquivo.

Aqui o eco vira gancho de verificação. O chamador traz as linhas REAIS do
arquivo e nós decidimos entre três desfechos:

- **exato** — o eco bate com o arquivo, segue;
- **reindentado** — bate só depois de ``strip()``. O modelo perdeu o recuo (é
  a falha mais comum: 4 espaços voltam como 1, ou nenhum). Sabemos o recuo
  certo, porque temos o arquivo, então reindentamos e seguimos;
- **recusado** — difere no conteúdo. Não há o que salvar, e postar um patch
  que não sabemos onde encaixa é exatamente como o problema nasceu.

Módulo puro de propósito: sem I/O, sem rede, sem banco. É a peça que precisa
de teste, e o teste não deve depender de GitHub nem de LLM.
"""
from __future__ import annotations

import ast
from dataclasses import dataclass


@dataclass(frozen=True)
class SubstituicaoVerificada:
    """Um trecho pronto para virar code suggestion e diff de exibição."""

    start_line: int
    end_line: int
    #: Linhas como estão no arquivo — a verdade, não o eco do modelo.
    original: list[str]
    #: Linhas novas, já reindentadas se foi preciso.
    replacement: list[str]
    #: `True` quando o recuo do modelo teve de ser corrigido.
    reindentado: bool

    def suggestion_body(self) -> str:
        """O conteúdo do bloco ```suggestion` — linhas literais, nada mais."""
        return "\n".join(self.replacement)

    def unified_diff(self, file_path: str) -> str:
        """Diff de EXIBIÇÃO, para o card do dashboard.

        Gerado aqui, e não pelo modelo, porque assim é sempre bem formado: o
        `DiffView` do front só precisa que as linhas comecem com `-`/`+`, e a
        contagem do cabeçalho `@@` fecha com o que está abaixo dele.
        """
        cabecalho = (
            f"--- a/{file_path}\n"
            f"+++ b/{file_path}\n"
            f"@@ -{self.start_line},{len(self.original)} "
            f"+{self.start_line},{len(self.replacement)} @@"
        )
        corpo = [f"-{linha}" for linha in self.original]
        corpo += [f"+{linha}" for linha in self.replacement]
        return "\n".join([cabecalho, *corpo])


class PatchInvalido(Exception):
    """A resposta do modelo não casa com o arquivo — não dá para postar."""


def _recuo(linha: str) -> str:
    return linha[: len(linha) - len(linha.lstrip())]


def _mapa_de_recuo(original: list[str], reais: list[str]) -> dict[int, set[int]]:
    """Aprende a correspondência entre o recuo do modelo e o do arquivo.

    Emparelha o eco com as linhas verdadeiras — elas já batem uma a uma
    (`verificar` só chega aqui depois de conferir o conteúdo) — e anota
    quantos espaços o modelo usou para cada nível que o arquivo usa.

    Substituiu o rebaseamento por recuo-base, que errava sempre que a
    PRIMEIRA linha do trecho estava na coluna 0: com base vazia dos dois
    lados, não havia o que trocar, e o recuo interno colapsado passava
    direto. Foi assim que um `def` com corpo de 1 espaço chegou a um PR.

    **O valor é um conjunto, não um número, de propósito.** Quando o modelo
    achata o trecho inteiro na coluna 0, um mesmo recuo dele corresponde a
    dois do arquivo (o `def` a 4 e o corpo a 8). Guardar só o último fazia o
    `def` e o corpo caírem no mesmo nível, e o erro só aparecia lá na frente,
    como um `IndentationError` do `ast` que não dizia a causa. Com o conjunto,
    a ambiguidade fica explícita e quem usa o mapa decide o que fazer.
    """
    mapa: dict[int, set[int]] = {}
    for do_modelo, real in zip(original, reais):
        if do_modelo.strip():
            mapa.setdefault(len(_recuo(do_modelo)), set()).add(len(_recuo(real)))
    return mapa


def _usa_tab(linhas: list[str]) -> bool:
    return any("\t" in _recuo(linha) for linha in linhas)


def _reindentar(linhas: list[str], mapa: dict[int, set[int]]) -> list[str]:
    """Reescreve o recuo de cada linha segundo o mapa aprendido.

    Um nível que não aparece no eco (código novo mais aninhado do que
    qualquer linha original) é escalado pela proporção observada — se o
    modelo escreve 1 espaço onde o arquivo tem 4, dois níveis dele viram
    oito espaços.

    Recusa quando o nível de uma linha é **ambíguo**: o modelo achatou o
    trecho e aquele mesmo recuo corresponde a mais de um do arquivo. Aí a
    informação de estrutura se perdeu na ida, e não há o que deduzir de volta
    — inventar um nível daria um patch plausível e errado.

    ponytail: escala linear, deduzida do maior par observado. Não cobre
    recuo irregular dentro do mesmo trecho. A rede de segurança é
    `_validar_sintaxe`, que recusa o resultado se ele não for Python válido.
    """
    if not mapa:
        return linhas
    niveis = [largura for largura in mapa if largura > 0]
    escala = (max(mapa[max(niveis)]) / max(niveis)) if niveis else 1.0

    saida = []
    for linha in linhas:
        if not linha.strip():
            saida.append("")
            continue
        largura = len(_recuo(linha))
        alvos = mapa.get(largura)
        if alvos is None:
            alvo = round(largura * escala)
        elif len(alvos) > 1:
            raise PatchInvalido(
                f"eco achatado: o recuo {largura} do modelo corresponde a "
                f"{sorted(alvos)} no arquivo — estrutura irrecuperavel"
            )
        else:
            alvo = next(iter(alvos))
        saida.append(" " * alvo + linha.lstrip())
    return saida


def _validar_sintaxe(
    file_path: str,
    linhas_do_arquivo: list[str],
    start_line: int,
    end_line: int,
    replacement: list[str],
) -> None:
    """Monta o arquivo com o trecho trocado e confere se ainda compila.

    Só para `.py`, e é a razão de o reparo de recuo poder ser heurístico: o
    `ast.parse` não opina sobre estilo, ele diz se o resultado é válido. Um
    recuo remendado errado vira `IndentationError` aqui em vez de virar um
    "Apply suggestion" que quebra o arquivo de quem clicou.

    Arquivo que já não compilava antes da troca passa — o problema não é
    nosso, e recusar seria punir o patch pelo estado prévio do repositório.
    """
    if not file_path.endswith(".py"):
        return

    origem = "\n".join(linhas_do_arquivo)
    try:
        ast.parse(origem)
    except SyntaxError:
        return  # já estava quebrado; não é a substituição que quebra

    resultado = (
        linhas_do_arquivo[: start_line - 1] + replacement + linhas_do_arquivo[end_line:]
    )
    try:
        ast.parse("\n".join(resultado))
    except SyntaxError as exc:
        raise PatchInvalido(
            f"o trecho substituido nao compila: {exc.msg} (linha {exc.lineno})"
        ) from exc


def _recusar_se_nao_muda(replacement: list[str], reais: list[str]) -> None:
    """Recusa sugestão que devolve o trecho igual ao que já está lá.

    Acontece de verdade: o modelo às vezes ecoa a linha vulnerável como se
    fosse a correção. Bem formada, verificada, e inútil — vira um comentário
    no PR cujo "Apply suggestion" não muda nada, e faz o revisor perder tempo
    conferindo por que aquilo está ali.
    """
    if replacement == reais:
        raise PatchInvalido("replacement identico ao original")


def verificar(
    *,
    start_line: int,
    end_line: int,
    original: list[str],
    replacement: list[str],
    linhas_do_arquivo: list[str],
    file_path: str = "",
) -> SubstituicaoVerificada:
    """Confere o trecho contra o arquivo e devolve a substituição pronta.

    ``linhas_do_arquivo`` é o arquivo inteiro, já dividido em linhas (índice 0
    = linha 1). Levanta ``PatchInvalido`` em tudo que não dê para garantir.
    """
    if not replacement:
        raise PatchInvalido("replacement vazio")
    if start_line < 1 or end_line < start_line:
        raise PatchInvalido(f"intervalo invalido: {start_line}-{end_line}")
    if end_line > len(linhas_do_arquivo):
        raise PatchInvalido(
            f"intervalo {start_line}-{end_line} passa do fim do arquivo "
            f"({len(linhas_do_arquivo)} linhas)"
        )

    reais = linhas_do_arquivo[start_line - 1 : end_line]
    if len(original) != len(reais):
        raise PatchInvalido(
            f"original tem {len(original)} linha(s), o intervalo tem {len(reais)}"
        )

    if original == reais:
        _recusar_se_nao_muda(replacement, reais)
        _validar_sintaxe(file_path, linhas_do_arquivo, start_line, end_line, replacement)
        return SubstituicaoVerificada(
            start_line=start_line,
            end_line=end_line,
            original=reais,
            replacement=replacement,
            reindentado=False,
        )

    # Mesmo conteúdo, recuo diferente: é a falha conhecida do modelo, e ela
    # tem conserto porque o recuo certo está no arquivo.
    if [linha.strip() for linha in original] != [linha.strip() for linha in reais]:
        raise PatchInvalido("original nao corresponde ao arquivo")

    # ponytail: reparo só com espaços. Arquivo indentado com tab sai por aqui
    #           em vez de ser reescrito com espaços — recusar é melhor do que
    #           misturar. Trocar por deteção do caractere se aparecer na prática.
    if _usa_tab(reais) or _usa_tab(replacement):
        raise PatchInvalido("recuo com tab: nao reindentado")

    reindentado = _reindentar(replacement, _mapa_de_recuo(original, reais))
    # Depois do reparo, e não antes: o recuo colapsado faria um no-op parecer
    # mudança.
    _recusar_se_nao_muda(reindentado, reais)
    _validar_sintaxe(file_path, linhas_do_arquivo, start_line, end_line, reindentado)
    return SubstituicaoVerificada(
        start_line=start_line,
        end_line=end_line,
        original=reais,
        replacement=reindentado,
        reindentado=True,
    )
