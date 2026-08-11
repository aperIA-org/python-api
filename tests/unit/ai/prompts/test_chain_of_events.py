"""Testes do prompt chain_of_events.

Foco principal: **o Tier 2 não fala de CTI nem de Caldera.**

Os dois só existem no Tier 3 — o enriquecimento do OpenCTI e a emulação do
Caldera rodam *depois* desta análise. O prompt já carregou blocos "Dados CTI"/
"Dados Caldera" e campos ``cti_status``/``caldera_status`` no schema de saída,
sempre vazios porque o único chamador em produção nunca passou esses dados. O
resultado era um rodapé fixo de ``unavailable`` no relatório do Tier 2, que
sugeria falha onde não houve tentativa.

A blindagem contra alucinação que motivava aqueles testes **continua valendo** e
mudou de forma: em vez de "se o bloco disser que não há dados, responda
unavailable", o SYSTEM agora proíbe de saída mencionar campanhas/atores/grupos e
afirmar exploração bem-sucedida (regra 2). E a antiga proteção contra payload
arbitrário do OpenCTI vazar para o prompt virou algo mais forte: ``build()`` não
aceita mais esses dados, então não há por onde vazar.
"""
import re

import pytest

from app.infrastructure.ai.prompts import chain_of_events


_FINDINGS_SAMPLE = [
    {
        "severity": "high",
        "source": "semgrep",
        "title": "SQL injection",
        "file_path": "app/db.py",
        "line_number": 42,
    },
    {
        "severity": "critical",
        "source": "trufflehog",
        "title": "AWS key",
        "file_path": "config/.env",
        "line_number": 1,
    },
]


def _bloco_de_regras(system: str, cabecalho: str, fim: str) -> str:
    """Recorta a lista de REGRAS do SYSTEM.

    O schema de saída também tem linhas numeradas, então contar regras no
    SYSTEM inteiro daria falso positivo.
    """
    inicio = system.index(cabecalho) + len(cabecalho)
    return system[inicio : system.index(fim, inicio)]


class TestSemCtiNemCaldera:
    """Regressão principal: nada de CTI/Caldera atravessa o Tier 2."""

    def test_prompt_nao_menciona_cti_nem_caldera(self):
        prompt = chain_of_events.build(
            findings=_FINDINGS_SAMPLE, context={"commit": "abc123"}
        )
        assert "Dados CTI" not in prompt
        assert "Dados Caldera" not in prompt
        # Mais forte que só os rótulos dos blocos: as palavras não aparecem em
        # lugar nenhum do prompt (a amostra de findings não as contém).
        assert "CTI" not in prompt
        assert "Caldera" not in prompt

    def test_prompt_tem_somente_commit_e_findings(self):
        """Lock do formato inteiro — qualquer bloco novo quebra aqui."""
        assert chain_of_events.build(findings=[]) == (
            "Commit: N/A\n\nFindings (0):\n(nenhum finding fornecido)\n"
        )

    def test_build_recusa_cti_data(self):
        with pytest.raises(TypeError):
            chain_of_events.build(
                findings=_FINDINGS_SAMPLE,
                cti_data={"active_campaigns": True},
            )

    def test_build_recusa_caldera_results(self):
        with pytest.raises(TypeError):
            chain_of_events.build(
                findings=_FINDINGS_SAMPLE,
                caldera_results={"success_rate": 0.5},
            )

    def test_build_recusa_a_assinatura_posicional_antiga(self):
        """`build(findings, cti_data, caldera_results, context)` não existe mais.

        O segundo posicional hoje é `context`: sem este teste, um chamador
        antigo passaria um dict de CTI como contexto e o prompt sairia com
        `Commit: N/A` silenciosamente.
        """
        with pytest.raises(TypeError):
            chain_of_events.build(_FINDINGS_SAMPLE, None, None, {"commit": "abc"})


class TestFindingsRendering:
    def test_empty_findings_yields_explicit_message(self):
        prompt = chain_of_events.build(findings=[])
        assert "(nenhum finding fornecido)" in prompt
        assert "Findings (0)" in prompt

    def test_findings_count_in_header(self):
        prompt = chain_of_events.build(findings=_FINDINGS_SAMPLE)
        assert "Findings (2)" in prompt

    def test_finding_severity_uppercase(self):
        prompt = chain_of_events.build(findings=_FINDINGS_SAMPLE)
        assert "[HIGH]" in prompt
        assert "[CRITICAL]" in prompt


class TestSystemPrompt:
    def test_system_mentions_no_invention_rule(self):
        assert "NÃO invente" in chain_of_events.SYSTEM

    def test_system_proibe_mencionar_campanhas_atores_e_grupos(self):
        """Substitui `test_system_explicitly_forbids_inventing_cti`.

        A proibição não é mais condicionada a um bloco "sem dados CTI": é
        incondicional, porque o Tier 2 nunca recebe inteligência externa.
        """
        assert (
            "NÃO mencione campanhas ativas, atores ou grupos de ameaça"
            in chain_of_events.SYSTEM
        )

    def test_system_proibe_afirmar_exploracao_bem_sucedida(self):
        assert (
            "NÃO afirme que uma exploração teve sucesso" in chain_of_events.SYSTEM
        )

    def test_system_diz_por_que_a_proibicao_existe(self):
        """A justificativa está no prompt de propósito: instrução sem motivo é
        mais fácil de o modelo relativizar."""
        assert (
            "não recebe inteligência externa nem resultado de emulação"
            in chain_of_events.SYSTEM
        )

    def test_schema_de_saida_nao_tem_status_de_inteligencia(self):
        assert "cti_status" not in chain_of_events.SYSTEM
        assert "caldera_status" not in chain_of_events.SYSTEM
        assert "unavailable" not in chain_of_events.SYSTEM

    def test_schema_termina_em_attack_narrative(self):
        assert chain_of_events.SYSTEM.rstrip().endswith(
            '"attack_narrative": "<string>"\n}'
        )

    def test_regras_numeradas_em_sequencia(self):
        """As regras foram renumeradas ao fundir 2 e 3 — buraco ou número
        repetido na lista confunde o modelo tanto quanto a regra faltando."""
        bloco = _bloco_de_regras(
            chain_of_events.SYSTEM, "REGRAS INVIOLÁVEIS:", "Formato de saída"
        )
        numeros = [int(n) for n in re.findall(r"^(\d+)\. ", bloco, re.MULTILINE)]
        assert numeros == list(range(1, len(numeros) + 1))
        assert len(numeros) == 5


class TestContextHandling:
    def test_commit_in_header_when_provided(self):
        prompt = chain_of_events.build(findings=[], context={"commit": "abc123"})
        assert "Commit: abc123" in prompt

    def test_no_context_yields_na(self):
        prompt = chain_of_events.build(findings=[])
        assert "Commit: N/A" in prompt
