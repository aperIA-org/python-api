"""Classificação determinística de como um finding foi validado.

O produto vende Attack Path Validation — separar "sinalizado" de "confirmado".
Antes, só o Caldera contava como validação, e ele é emulação de host: para alvo
web dizia "validado: não" sobre achados que TruffleHog e ZAP já confirmaram.
"""
from app.domain.finding.validation import (
    MetodoValidacao,
    classificar,
    confirmado,
    resumo,
)


def _zap(*, attack="", confidence="Medium", title="ZAP alert"):
    return {
        "source": "zap",
        "title": title,
        "raw_output": {"attack": attack, "confidence": confidence},
    }


def test_secret_verificado_e_a_validacao_mais_forte():
    f = {"source": "trufflehog", "secret_verified": True, "title": "AWS key"}
    assert classificar(f) is MetodoValidacao.SECRET_VIVO
    assert confirmado(MetodoValidacao.SECRET_VIVO)


def test_secret_nao_verificado_nao_valida():
    """Um segredo achado mas não verificado é candidato, não confirmação."""
    f = {"source": "trufflehog", "secret_verified": False, "title": "maybe key"}
    assert classificar(f) is MetodoValidacao.NAO_VALIDADO


def test_zap_com_attack_e_exploracao_ativa():
    """`attack` só aparece quando o active scanner enviou um payload."""
    f = _zap(attack="<script>alert(1)</script>", confidence="Medium")
    assert classificar(f) is MetodoValidacao.ZAP_ATIVO
    assert confirmado(MetodoValidacao.ZAP_ATIVO)


def test_zap_passivo_alta_confianca_e_observacao():
    """Cabeçalho ausente: confirmado por observação direta, não exploração."""
    f = _zap(attack="", confidence="High")
    assert classificar(f) is MetodoValidacao.ZAP_OBSERVADO
    assert confirmado(MetodoValidacao.ZAP_OBSERVADO)


def test_zap_confirmed_tambem_conta_como_observado():
    assert classificar(_zap(confidence="Confirmed")) is MetodoValidacao.ZAP_OBSERVADO


def test_zap_passivo_baixa_confianca_nao_valida():
    """Conservador de propósito: sub-declarar é melhor que super-declarar."""
    assert classificar(_zap(confidence="Medium")) is MetodoValidacao.NAO_VALIDADO
    assert classificar(_zap(confidence="Low")) is MetodoValidacao.NAO_VALIDADO


def test_active_scan_vence_alta_confianca():
    """Tendo payload enviado, é exploração ativa mesmo com confiança alta."""
    assert classificar(_zap(attack="x", confidence="High")) is MetodoValidacao.ZAP_ATIVO


def test_semgrep_estatico_nunca_valida():
    """Análise estática acha padrão no código; não confirma contra sistema vivo."""
    f = {"source": "semgrep", "title": "SQL injection", "raw_output": {}}
    assert classificar(f) is MetodoValidacao.NAO_VALIDADO
    assert not confirmado(MetodoValidacao.NAO_VALIDADO)


def test_raw_output_ausente_ou_invalido_nao_quebra():
    assert classificar({"source": "zap"}) is MetodoValidacao.NAO_VALIDADO
    assert classificar({"source": "zap", "raw_output": None}) is MetodoValidacao.NAO_VALIDADO
    assert classificar({}) is MetodoValidacao.NAO_VALIDADO


def test_resumo_conta_confirmados_e_agrupa_por_metodo():
    findings = [
        {"source": "trufflehog", "secret_verified": True, "title": "AWS key"},
        _zap(attack="x", title="XSS refletido"),
        _zap(confidence="High", title="CSP ausente"),
        _zap(confidence="High", title="CSP ausente"),  # repete: mesma rota+1
        {"source": "semgrep", "title": "SQLi", "raw_output": {}},
    ]
    r = resumo(findings)

    assert r["total"] == 5
    assert r["confirmados"] == 4  # 1 secret + 1 ativo + 2 observados
    metodos = {g["metodo"]: g for g in r["grupos"]}
    assert metodos["secret_vivo"]["total"] == 1
    assert metodos["zap_observado"]["total"] == 2
    # exemplos deduplicam o título repetido
    assert metodos["zap_observado"]["exemplos"] == ["CSP ausente"]
    assert metodos["nao_validado"]["total"] == 1
    assert metodos["nao_validado"]["confirmado"] is False


def test_resumo_ordena_do_mais_forte_ao_nao_validado():
    findings = [
        {"source": "semgrep", "title": "SQLi", "raw_output": {}},
        {"source": "trufflehog", "secret_verified": True, "title": "key"},
    ]
    ordem = [g["metodo"] for g in resumo(findings)["grupos"]]
    assert ordem == ["secret_vivo", "nao_validado"]


def test_resumo_vazio():
    r = resumo([])
    assert r == {"grupos": [], "total": 0, "confirmados": 0}
