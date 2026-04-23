from typing import Protocol, runtime_checkable


@runtime_checkable
class PasswordVerifier(Protocol):
    """
    Protocolo para verificacao de senha.
    Permite substituir a implementacao real por um mock em testes
    sem depender de infra externa (Argon2).
    """

    def verify(self, hashed: str, plain: str) -> bool:
        ...
