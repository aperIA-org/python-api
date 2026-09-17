"""Teto de findings nos prompts que produzem JSON.

O `pr_report` já cortava em 40, porque ele estourou a janela de contexto quando
o ZAP passou a funcionar. Os dois prompts de **raciocínio** —
``chain_of_events`` e ``attack_path`` — não cortavam nada, e o problema chegou
por outro lado: não pela entrada, pela **saída**.

Com 102 findings no prompt, o modelo escreveu uma cadeia longa demais e a
resposta bateu no ``max_tokens``. JSON truncado no meio de uma string virou
``Unterminated string`` no ``json.loads``, e os Tiers 2 e 3 caíram em modo
degradado juntos — sem attack path, sem impacto ao negócio, sem veredito. Ou
seja: os dois prompts cujo resultado é consumido por máquina eram justamente os
sem teto.

O teto aqui é mais generoso que o do relatório (60 contra 40) porque o critério
é diferente. O relatório precisa caber no que uma pessoa lê; a cadeia de ataque
precisa **ver** o suficiente para correlacionar. Cortar fundo demais aqui
inventaria uma cadeia mais curta que a realidade, que é pior que uma cadeia
longa.
"""
from __future__ import annotations

_TETO = 60

_RANK_SEVERIDADE = {"critical": 5, "high": 4, "medium": 3, "low": 2, "info": 1}


def _rank(finding: object) -> int:
    if not isinstance(finding, dict):
        return 0
    return _RANK_SEVERIDADE.get(str(finding.get("severity", "")).lower(), 0)


def limitar(findings: list[dict], teto: int = _TETO) -> tuple[list[dict], str]:
    """Devolve os ``teto`` findings mais severos e uma nota sobre o que sobrou.

    A nota **não** é decorativa: sem ela o modelo conclui que viu o conjunto
    inteiro e passa a afirmar completude que ele não tem. É a mesma razão pela
    qual o ``pr_report`` emite ``findings_resumo`` — e vale mais aqui, porque
    ``kill_chain_complete`` é uma afirmação explícita sobre a cadeia estar
    fechada.

    Devolve string vazia quando nada foi cortado, para o prompt não carregar uma
    ressalva que não se aplica.
    """
    if not isinstance(findings, list) or len(findings) <= teto:
        return (findings if isinstance(findings, list) else []), ""

    ordenados = sorted(findings, key=_rank, reverse=True)
    incluidos = ordenados[:teto]

    por_severidade: dict[str, int] = {}
    for f in ordenados[teto:]:
        sev = str((f or {}).get("severity", "desconhecida")).lower()
        por_severidade[sev] = por_severidade.get(sev, 0) + 1
    detalhe = ", ".join(f"{n} {sev}" for sev, n in sorted(por_severidade.items()))

    nota = (
        f"ATENCAO: o commit tem {len(findings)} findings; abaixo estao os {teto} "
        f"mais severos. Ficaram de fora {len(findings) - teto} ({detalhe}). "
        "Nao afirme que a cadeia esta completa apenas por nao ver mais findings — "
        "se a amostra nao sustentar o fechamento, use kill_chain_complete: false."
    )
    return incluidos, nota
