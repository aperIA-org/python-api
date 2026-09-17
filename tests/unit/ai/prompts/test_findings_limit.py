"""Teto de findings nos prompts de raciocinio.

Regressao do incidente: 102 findings entravam sem corte em `chain_of_events` e
`attack_path`, a resposta batia em `max_tokens` e os Tiers 2 e 3 caiam em modo
degradado juntos.
"""
from app.infrastructure.ai.prompts import attack_path, chain_of_events
from app.infrastructure.ai.prompts._findings_limit import limitar


def _findings(quantidade: int, severidade: str = "medium") -> list[dict]:
    return [
        {
            "severity": severidade,
            "source": "semgrep",
            "title": f"regra-{i}",
            "file_path": f"app/f{i}.py",
            "line_number": i,
        }
        for i in range(quantidade)
    ]


class TestLimitar:
    def test_abaixo_do_teto_nao_corta_nem_avisa(self):
        findings = _findings(10)
        incluidos, nota = limitar(findings)
        assert incluidos == findings
        # Sem corte, sem ressalva: o prompt nao carrega aviso que nao se aplica.
        assert nota == ""

    def test_acima_do_teto_corta_e_avisa(self):
        incluidos, nota = limitar(_findings(150))
        assert len(incluidos) == 60
        assert "150 findings" in nota
        assert "90" in nota

    def test_mantem_os_mais_severos(self):
        """O corte por severidade e o ponto: cortar os criticos inverteria o produto."""
        findings = _findings(80, "low") + _findings(5, "critical")
        incluidos, _ = limitar(findings)
        criticos = [f for f in incluidos if f["severity"] == "critical"]
        assert len(criticos) == 5

    def test_nota_desencoraja_afirmar_cadeia_completa(self):
        """Sem isso o modelo conclui que viu tudo e afirma completude falsa."""
        _, nota = limitar(_findings(150))
        assert "kill_chain_complete" in nota

    def test_severidade_desconhecida_nao_quebra(self):
        incluidos, _ = limitar([{"severity": "esquisita"}] * 70)
        assert len(incluidos) == 60

    def test_entrada_nao_lista_devolve_vazio(self):
        assert limitar(None) == ([], "")


class TestPromptsAplicamOTeto:
    def test_chain_of_events_corta_e_declara_o_total(self):
        prompt = chain_of_events.build(_findings(150), {"commit": "abc123"})
        # A contagem exibida e a TOTAL, nao a da amostra — esconder o corte do
        # modelo que precisa saber dele seria o mesmo defeito de outra forma.
        assert "Findings (150)" in prompt
        assert "ATENCAO" in prompt
        assert prompt.count("regra-") == 60

    def test_chain_of_events_sem_corte_nao_tem_atencao(self):
        prompt = chain_of_events.build(_findings(10), {"commit": "abc123"})
        assert "ATENCAO" not in prompt
        assert "Findings (10)" in prompt

    def test_attack_path_corta_e_declara_o_total(self):
        prompt = attack_path.build(_findings(150), None, None, {"commit": "abc123"})
        assert "Findings (150)" in prompt
        assert "ATENCAO" in prompt
        assert prompt.count("regra-") == 60

    def test_attack_path_preserva_os_outros_blocos(self):
        """O corte nao pode comer CTI/Caldera/validacao."""
        prompt = attack_path.build(_findings(150), None, None, {"commit": "abc"})
        assert "Dados CTI:" in prompt
        assert "Dados Caldera:" in prompt
        assert "Validacao por evidencia:" in prompt
