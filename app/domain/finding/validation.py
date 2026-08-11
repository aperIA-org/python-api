"""Como um finding foi **confirmado** — e por qual evidência.

Motivação. A promessa do produto é *Attack Path Validation*: separar "o scanner
sinalizou" de "confirmamos que é explorável". Até aqui a única validação que o
relatório reconhecia era a do Caldera — emulação de adversário de **host**. Para
um alvo **web**, o Caldera valida mal por incompatibilidade de categoria
(emular `find / -name '*.pem'` no sandbox não diz nada sobre a chave vazada no
Juice Shop), então o relatório dizia "validado: não" para achados que a própria
cadeia de ferramentas confirmou.

Este módulo torna esse sinal explícito e **determinístico** — computado da
evidência do scanner, não pedido a um LLM (instrução não é contrato). Três
fontes já confirmam achados web hoje, e cada uma confirma de um jeito diferente:

- **TruffleHog** verifica o segredo contra o provedor (`secret_verified`): a
  credencial *funciona*. É a validação mais forte que existe.
- **ZAP active scan** envia um payload e observa a resposta vulnerável (o alerta
  carrega `attack`): exploração de verdade contra o alvo implantado.
- **ZAP passivo de alta confiança** observa a condição diretamente na resposta
  (cabeçalho ausente, divulgação de informação): confirmado por observação, não
  por exploração — um estado intermediário honesto.

O que **não** é validado por aqui é igualmente importante: um achado estático do
Semgrep é um *candidato* — o padrão está no código, mas nada foi confirmado
contra um sistema vivo. Marcá-lo como não validado é o ponto, não uma lacuna.

A validação do Caldera continua vindo do `caldera_results` (por passo do attack
path), separada: as duas convivem no relatório.
"""
from __future__ import annotations

from collections.abc import Mapping
from enum import Enum


class MetodoValidacao(str, Enum):
    """Como um finding foi confirmado, do mais forte ao não-confirmado."""

    SECRET_VIVO = "secret_vivo"
    ZAP_ATIVO = "zap_ativo"
    ZAP_OBSERVADO = "zap_observado"
    NAO_VALIDADO = "nao_validado"


#: Rótulo PT-BR de cada método, para o relatório.
ROTULO: dict[MetodoValidacao, str] = {
    MetodoValidacao.SECRET_VIVO: "credencial verificada como válida",
    MetodoValidacao.ZAP_ATIVO: "explorada por active scan (payload enviado ao alvo)",
    MetodoValidacao.ZAP_OBSERVADO: "confirmada por observação direta no alvo",
    MetodoValidacao.NAO_VALIDADO: (
        "sinalizada por análise — não confirmada contra sistema vivo"
    ),
}

#: Confiança do ZAP que conta como "observado". Abaixo disso é conservador
#: (não validado): sub-declarar validação é preferível a super-declarar.
_CONFIANCA_OBSERVAVEL = {"high", "confirmed", "user confirmed"}

#: Métodos que confirmam o achado contra o alvo vivo (por ação ou observação).
#: O Caldera não entra: sua validação é por passo do attack path, não por finding.
_CONFIRMADOS = frozenset(
    {
        MetodoValidacao.SECRET_VIVO,
        MetodoValidacao.ZAP_ATIVO,
        MetodoValidacao.ZAP_OBSERVADO,
    }
)


def confirmado(metodo: MetodoValidacao) -> bool:
    """Se o método confirma o achado contra um sistema vivo.

    `NAO_VALIDADO` é o único que não confirma — é o achado estático que ainda é
    só um candidato.
    """
    return metodo in _CONFIRMADOS


def classificar(finding: Mapping[str, object]) -> MetodoValidacao:
    """Deriva o método de validação de um finding **serializado** (dict).

    Opera no dict porque é essa a forma que trafega no canvas Celery; as chaves
    espelham os campos de ``Finding``. Puro e sem I/O — a evidência já está no
    próprio finding (`secret_verified`, `raw_output`).
    """
    source = str(finding.get("source") or "").lower()

    if source == "trufflehog" and bool(finding.get("secret_verified")):
        return MetodoValidacao.SECRET_VIVO

    if source == "zap":
        raw = finding.get("raw_output")
        raw = raw if isinstance(raw, Mapping) else {}
        # `attack` só existe quando o active scanner enviou um payload — é a
        # marca de exploração, não de observação passiva.
        if str(raw.get("attack") or "").strip():
            return MetodoValidacao.ZAP_ATIVO
        confianca = str(raw.get("confidence") or "").strip().lower()
        if confianca in _CONFIANCA_OBSERVAVEL:
            return MetodoValidacao.ZAP_OBSERVADO

    return MetodoValidacao.NAO_VALIDADO


def resumo(findings: list[Mapping[str, object]]) -> dict:
    """Agrega a validação de uma lista de findings, para o relatório.

    Retorna, por método (na ordem do enum, mais forte primeiro): a contagem e
    até três títulos de exemplo. `confirmados` é o total que a cadeia de
    ferramentas confirmou contra o alvo — o número que responde "o que aqui é
    real, não só sinalizado".
    """
    por_metodo: dict[MetodoValidacao, list[str]] = {m: [] for m in MetodoValidacao}
    for finding in findings:
        metodo = classificar(finding)
        por_metodo[metodo].append(str(finding.get("title") or "sem título"))

    grupos = []
    confirmados = 0
    for metodo in MetodoValidacao:
        titulos = por_metodo[metodo]
        if not titulos:
            continue
        if confirmado(metodo):
            confirmados += len(titulos)
        # dedup preservando ordem: o mesmo tipo de alerta repete por rota
        exemplos: list[str] = []
        for t in titulos:
            if t not in exemplos:
                exemplos.append(t)
            if len(exemplos) == 3:
                break
        grupos.append(
            {
                "metodo": metodo.value,
                "rotulo": ROTULO[metodo],
                "confirmado": confirmado(metodo),
                "total": len(titulos),
                "exemplos": exemplos,
            }
        )

    return {
        "grupos": grupos,
        "total": len(findings),
        "confirmados": confirmados,
    }
