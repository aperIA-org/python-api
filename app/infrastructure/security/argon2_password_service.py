from argon2 import PasswordHasher
from argon2.exceptions import InvalidHashError, VerificationError, VerifyMismatchError


class Argon2PasswordService:
    """
    Implementacao concreta de PasswordVerifier usando Argon2id.
    Injetada no LoginUseCase via dependencia - nunca instanciada dentro do use case.
    """

    def __init__(self) -> None:
        self._ph = PasswordHasher()

    def verify(self, hashed: str, plain: str) -> bool:
        try:
            return self._ph.verify(hashed, plain)
        except (VerifyMismatchError, VerificationError, InvalidHashError):
            return False
