"""Segredo real não sai da infraestrutura — nem derruba a análise por IA.

Regressão do incidente do Juice Shop: o repositório contém uma chave privada
real; o TruffleHog a reportou (é o trabalho dele) e o `Raw` foi parar na
`description` do finding, que o prompt do relatório do Tier 2 inclui. A guarda
anti-prompt-injection casou `BEGIN RSA PRIVATE KEY` e bloqueou a chamada, então
o Tier 2 caiu em modo degradado — quanto melhor o scanner trabalhava, menos
análise o usuário recebia.
"""
from unittest.mock import MagicMock

import pytest

from app.infrastructure.ai.claude_client import ClaudeClient
from app.infrastructure.ai.llm_guard_client import LLMGuardClient, redigir_segredos

PEM = (
    "-----BEGIN RSA PRIVATE KEY-----\n"
    "MIICXAIBAAKBgQDNwqLEe9wgTXCbFAKEFAKEFAKE\n"
    "-----END RSA PRIVATE KEY-----"
)


def test_pem_completo_e_redigido():
    texto, n = redigir_segredos(f"antes {PEM} depois")
    assert n == 1
    assert "BEGIN RSA PRIVATE KEY" not in texto
    assert "MIICXAIBAAKBgQ" not in texto
    assert "antes" in texto and "depois" in texto


def test_pem_truncado_sem_END_tambem_e_redigido():
    """O `Raw` do TruffleHog pode vir cortado — não pode escapar por isso."""
    texto, n = redigir_segredos(
        "- [MEDIUM] trufflehog: PrivateKey\n-----BEGIN PRIVATE KEY-----\nMIIBVQIBADAN"
    )
    assert n == 1
    assert "MIIBVQIBADAN" not in texto


def test_texto_sem_segredo_nao_muda():
    original = "- [HIGH] semgrep: SQL injection (arquivo: app/db.py:42)"
    texto, n = redigir_segredos(original)
    assert n == 0
    assert texto == original


def test_guarda_bloqueava_antes_e_aprova_depois():
    guard = LLMGuardClient()
    assert guard.check(PEM).safe is False
    assert guard.check(redigir_segredos(PEM)[0]).safe is True


def test_claude_recebe_prompt_redigido_e_nao_bloqueia():
    """O ponto de estrangulamento: o segredo não chega à API da Anthropic."""
    anthropic = MagicMock()
    mensagem = MagicMock()
    mensagem.content = [MagicMock(text="ok")]
    mensagem.usage = MagicMock(
        input_tokens=1, output_tokens=1,
        cache_read_input_tokens=0, cache_creation_input_tokens=0,
    )
    anthropic.messages.create.return_value = mensagem

    cliente = ClaudeClient(api_key="k", anthropic_client=anthropic)
    cliente.call(system="s", user=f"findings:\n{PEM}", model="m", commit_sha="a" * 40)

    enviado = anthropic.messages.create.call_args[1]["messages"][0]["content"]
    assert "BEGIN RSA PRIVATE KEY" not in enviado
    assert "MIICXAIBAAKBgQ" not in enviado
    assert "redigida" in enviado
