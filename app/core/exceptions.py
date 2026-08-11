"""Exceções de domínio compartilhadas entre camadas.

Por que estão em ``core/`` e não em ``domain/``:
- O domínio define **regras de negócio**, não erros operacionais.
- Estas exceções modelam falhas transversais (sandbox quebrada,
  pipeline interrompido, scanner indisponível) que cruzam camadas e
  são lançadas tanto em ``infrastructure/`` quanto em
  ``application/``.
"""
from __future__ import annotations


class AperiaError(Exception):
    """Base de todas as exceções aperIA — facilita catch genérico."""


class SandboxViolationError(AperiaError):
    """Caldera ou outro componente foi iniciado fora do sandbox isolado.

    Levantada no ``__init__`` do client; nenhuma operação prossegue.
    """


class PipelineHaltedError(AperiaError):
    """Gate parou o pipeline intencionalmente (ex: Gate 1 com secret verificado).

    Convertida em ``celery.exceptions.Ignore`` no canvas do Celery
    para interromper o chain sem propagar erro.
    """


class RepoCheckoutError(AperiaError):
    """Não foi possível materializar a árvore do commit em disco.

    Cobre tudo que impede o checkout efêmero: token de instalação recusado,
    repositório removido/renomeado, commit inexistente (force-push), rede
    pendurada (timeout). Diferente das falhas de scanner, esta **não** é
    best-effort: sem os arquivos não há o que escanear, então a task falha e
    encerra os tiers pendentes do ``ScanJob``.
    """


class ScanDispatchError(AperiaError):
    """O pipeline não pôde ser enfileirado (broker/result backend indisponível).

    Distinta das falhas de execução: aqui nada chegou a rodar. A rota converte
    em **503** com mensagem acionável, em vez de deixar vazar um 500 anônimo —
    o usuário precisa saber que o problema é de infraestrutura e que tentar de
    novo faz sentido, não que o repositório dele tem algo errado.
    """


class FindingPersistenceError(AperiaError):
    """Findings foram encontrados mas não puderam ser gravados.

    Pelo mesmo motivo de ``RepoCheckoutError``, esta **não** é best-effort. A
    persistência já foi best-effort e escondeu um defeito real: um `cwe_id` de
    93 caracteres numa coluna de 50 fez o `INSERT` estourar, o erro virou
    warning, e o pipeline concluiu anunciando sucesso — com o finding visível no
    payload do canvas, alimentando o Tier 2, e ausente do banco. No dashboard
    isso é indistinguível de "repositório limpo".

    Um scan que perde o que encontrou não teve sucesso. Perder findings em
    silêncio é pior do que falhar: a falha é visível e reexecutável.
    """


class ScannerUnavailableError(AperiaError):
    """Scanner CLI não está instalado ou serviço externo está down.

    Espera-se que workers convertam em skip + warning, não failure.
    """


class LLMGuardBlockedError(AperiaError):
    """LLM Guard barrou o conteúdo antes de chegar ao Claude.

    Diferente de ``GuardBlockedError`` em ``ai/claude_client.py``:
    aquela é específica do client; esta é a versão de domínio que
    workers podem capturar sem importar do módulo de AI.
    """
