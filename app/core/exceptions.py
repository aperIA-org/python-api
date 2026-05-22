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
