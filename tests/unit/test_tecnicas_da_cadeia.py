"""Extração dos IDs MITRE do `event_chain` do Tier 2.

O campo vem de um LLM. Antes ele era usado verbatim (só `.strip().upper()`),
então `"T1059 - Command and Scripting"` entrava inteiro na lista, não casava com
ability nenhuma e a emulação rodava zero técnicas — sem erro, sem log, sem nada
que indicasse que o problema era formatação e não cobertura.
"""
from app.core.orchestrator import _tecnicas_da_cadeia


def _cadeia(*passos):
    return {"event_chain": list(passos)}


def test_extrai_subtecnica_e_tecnica_pai():
    assert _tecnicas_da_cadeia(
        _cadeia({"technique": "T1059.007"}, {"technique": "T1036"})
    ) == ["T1059.007", "T1036"]


def test_ignora_texto_em_volta_do_id():
    """O prompt pede só o identificador, mas instrução não é contrato."""
    assert _tecnicas_da_cadeia(
        _cadeia({"technique": "T1059 - Command and Scripting Interpreter"})
    ) == ["T1059"]


def test_normaliza_caixa():
    assert _tecnicas_da_cadeia(_cadeia({"technique": "t1552.001"})) == ["T1552.001"]


def test_usa_o_pai_como_resgate_quando_technique_falta():
    assert _tecnicas_da_cadeia(
        _cadeia({"technique": None, "technique_parent": "T1552"})
    ) == ["T1552"]


def test_prefere_sempre_a_subtecnica_ao_pai():
    """A sub-técnica descreve o achado; é contra ela que `caldera_validated`
    faz sentido. Somar o pai apagaria a distinção entre validação exata e
    parcial (ver `MapeamentoAbilities`)."""
    assert _tecnicas_da_cadeia(
        _cadeia({"technique": "T1059.007", "technique_parent": "T1059"})
    ) == ["T1059.007"]


def test_descarta_passos_sem_id_reconhecivel():
    assert _tecnicas_da_cadeia(
        _cadeia(
            {"technique": "null"},
            {"technique": ""},
            {"technique": "desconhecida"},
            "lixo",
            {"technique": "T1190"},
        )
    ) == ["T1190"]


def test_nao_repete_e_preserva_a_ordem_dos_passos():
    assert _tecnicas_da_cadeia(
        _cadeia(
            {"technique": "T1190"}, {"technique": "T1059"}, {"technique": "T1190"}
        )
    ) == ["T1190", "T1059"]


def test_cadeia_vazia_nao_quebra():
    assert _tecnicas_da_cadeia({}) == []
    assert _tecnicas_da_cadeia({"event_chain": None}) == []
