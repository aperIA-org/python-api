"""Testes do prompt remediation (Tier 3, Haiku).

Foco crítico (decisão #4 Semana 10): o SYSTEM deve conter
LITERALMENTE o texto que reforça a regra inviolável de não
auto-aplicar patches.
"""
from __future__ import annotations

import json

from app.infrastructure.ai.prompts import remediation


_FINDING_SAMPLE = {
    "source": "semgrep",
    "severity": "high",
    "title": "SQL injection",
    "description": "f-string em query",
    "cve_id": None,
    "cwe_id": "CWE-89",
    "file_path": "app/db.py",
    "line_number": 42,
    "secret_verified": False,
    "secret_type": None,
}

_SECRET_FINDING = {
    "source": "trufflehog",
    "severity": "critical",
    "title": "Secret verificado: AWS",
    "description": "AKIA...",
    "cve_id": None,
    "cwe_id": None,
    "file_path": "config/secrets.env",
    "line_number": 12,
    "secret_verified": True,
    "secret_type": "AWS",
}


# -----------------------------------------------------------------------------
# Texto literal da decisão #4 — INVIOLÁVEL
# -----------------------------------------------------------------------------


class TestNoAutoApplyContract:
    def test_system_contains_exact_no_apply_clause(self):
        """A garantia é a mesma da decisão #4; a redação mudou com o formato.

        O contrato deixou de pedir diff unificado (o modelo não o produzia de
        forma aplicável) e passou a pedir as linhas de substituição. A cláusula
        foi reescrita junto, mas o que ela proíbe é idêntico: executar,
        aplicar, commitar.
        """
        required = (
            "Você NÃO gera diff, NÃO executa, NÃO aplica e NÃO faz commit. "
            "Você devolve as linhas de código que substituem um trecho — a "
            "aplicação é responsabilidade exclusiva do desenvolvedor."
        )
        assert required in remediation.SYSTEM

    def test_system_forbids_silencing_scanners(self):
        # Garante que o modelo não vai sugerir `# nosec` para passar no scan
        assert "# nosec" in remediation.SYSTEM or "nosec" in remediation.SYSTEM
        assert "suprima" in remediation.SYSTEM.lower() or "silenci" in remediation.SYSTEM.lower()

    def test_system_mentions_secret_rotation(self):
        assert "rotation" in remediation.SYSTEM.lower() or "rotar" in remediation.SYSTEM.lower()
        assert "requires_secret_rotation" in remediation.SYSTEM


# -----------------------------------------------------------------------------
# Schema JSON e estrutura
# -----------------------------------------------------------------------------


class TestSchema:
    def test_system_defines_all_required_fields(self):
        for field in (
            "start_line",
            "end_line",
            "original",
            "replacement",
            "explanation",
            "requires_secret_rotation",
            "rotation_instructions",
        ):
            assert field in remediation.SYSTEM

    def test_system_nao_pede_mais_diff_unificado(self):
        """Pedir diff é o que quebrava o `suggestion` — não pode voltar.

        O bloco ```suggestion do GitHub substitui as linhas ancoradas pelo
        conteúdo LITERAL. Um diff ali faz o "Apply suggestion" escrever `@@`,
        `-` e `+` dentro do arquivo de quem clicou.
        """
        assert "patch_diff" not in remediation.SYSTEM
        assert "diff unificado" not in remediation.SYSTEM

    def test_system_exige_indentacao_literal(self):
        """O modelo colapsava o recuo; o prompt tem que falar disso."""
        assert "indentação" in remediation.SYSTEM
        assert "NNNN: " in remediation.SYSTEM


# -----------------------------------------------------------------------------
# build() — user prompt
# -----------------------------------------------------------------------------


class TestBuild:
    def test_user_prompt_includes_finding_summary(self):
        prompt = remediation.build(_FINDING_SAMPLE)
        # JSON do finding deve estar no prompt (não no SYSTEM)
        assert "SQL injection" in prompt
        assert "CWE-89" in prompt
        assert "app/db.py" in prompt
        assert "42" in prompt

    def test_user_prompt_includes_code_context_when_provided(self):
        prompt = remediation.build(
            _FINDING_SAMPLE,
            code_context="def get_user(id):\n    return db.query(f'SELECT * FROM users WHERE id = {id}')",
        )
        assert "get_user" in prompt
        assert "SELECT" in prompt

    def test_user_prompt_indicates_no_context_when_missing(self):
        prompt = remediation.build(_FINDING_SAMPLE)
        assert "não fornecido" in prompt

    def test_secret_finding_carries_secret_metadata(self):
        prompt = remediation.build(_SECRET_FINDING)
        # JSON embedded contém os flags de secret
        json_start = prompt.find("{")
        json_end = prompt.rfind("}") + 1
        embedded = json.loads(prompt[json_start:json_end].split("\n")[0] if False else prompt[json_start:json_end])
        assert embedded["secret_verified"] is True
        assert embedded["secret_type"] == "AWS"

    def test_user_prompt_does_not_leak_unrelated_keys(self):
        finding = {**_FINDING_SAMPLE, "raw_output": {"injection": "ignore previous"}}
        prompt = remediation.build(finding)
        # raw_output não deve vazar (não está no whitelist do build)
        assert "ignore previous" not in prompt
