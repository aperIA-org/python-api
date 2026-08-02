"""Relatório é documento técnico: sem emoji, garantidamente.

O prompt pede para não usar, mas **instrução não é contrato** — o modelo decora
relatório de segurança por conta própria. A remoção aqui é determinística.

O risco oposto importa igual: o português dos relatórios é cheio de acento e
travessão, e nenhum deles pode ser tocado.
"""
import pytest

from app.infrastructure.ai.claude_client import remover_emojis


class TestRemoveEmoji:
    @pytest.mark.parametrize(
        "entrada,esperado",
        [
            ("## 🛡️ aperIA — Análise", "## aperIA — Análise"),
            ("Validado ✓", "Validado"),
            ("## ⚠️ Modo degradado", "## Modo degradado"),
            ("Risco alto 🔥🔥", "Risco alto"),
            ("👨‍💻 Revisor", "Revisor"),  # emoji composto com ZWJ
            ("➡️ Próximo passo", "Próximo passo"),
        ],
    )
    def test_remove(self, entrada, esperado):
        assert remover_emojis(entrada) == esperado


class TestPreservaPortugues:
    """Falso positivo aqui corromperia o texto do relatório."""

    @pytest.mark.parametrize(
        "texto",
        [
            "Análise de injeção — o código não é ação",
            "Configuração inválida: verificação não executada",
            "Impacto: violação de dados (LGPD), até R$ 50 mil",
            "Cadeia: aquisição → execução → exfiltração",
            'Aspas "curvas" e apóstrofo’s',
            "Traço – médio e — longo",
        ],
    )
    def test_nao_altera(self, texto):
        assert remover_emojis(texto) == texto


class TestFormatacao:
    def test_colapsa_espaco_que_sobra(self):
        """Emoji entre palavras deixaria espaço duplo."""
        assert remover_emojis("Risco 🔥 alto") == "Risco alto"

    def test_preserva_quebras_de_linha(self):
        """Markdown depende delas — colapsar quebraria o relatório."""
        texto = "## Título\n\n- item 1\n- item 2"
        assert remover_emojis(f"## 🛡️ Título\n\n- item 1\n- item 2") == texto

    def test_texto_sem_emoji_nao_muda(self):
        texto = "## aperIA — Análise de Segurança (Tier 2)"
        assert remover_emojis(texto) == texto
