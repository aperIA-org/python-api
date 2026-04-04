import re
import unicodedata

from argon2 import PasswordHasher

from app.application.exceptions import UserValidationError
from app.domain.repositories.user_repository import UserRepository
from app.infrastructure.persistence.models.user_model import UserModel

password_hasher = PasswordHasher()
USERNAME_PATTERN = re.compile(r"^[A-Za-z0-9 ]+$")
MAX_PASSWORD_LENGTH = 128

class CreateUserUseCase:
    def __init__(self, user_repository: UserRepository) -> None:
        self.user_repository = user_repository

    def execute(
        self,
        username: str,
        password: str,
        email: str,
    ) -> UserModel:
        parsed_username = self._parse_input(username)
        parsed_password = self._parse_input(password)
        parsed_email = self._parse_input(email).lower()

        self._validate_username(parsed_username)
        self._validate_password(parsed_password)
        self._validate_email(parsed_email)

        hashed_password = password_hasher.hash(parsed_password)

        if self.user_repository.exists_by_email(parsed_email):
            raise UserValidationError("E-mail já cadastrado")

        return self.user_repository.insert(
            username=parsed_username,
            password=hashed_password,
            email=parsed_email,
        )

    def _parse_input(self, value: str) -> str:
        normalized = unicodedata.normalize("NFKC", value).strip()
        if not normalized:
            raise UserValidationError("Campos username, password e email sao obrigatorios")
        return normalized

    def _validate_email(self, email: str) -> None:
        if not re.fullmatch(r"^[^\s@]+@[^\s@]+\.[^\s@]+$", email):
            raise UserValidationError("E-mail invalido")

    def _validate_password(self, password: str) -> None:
        if len(password) > MAX_PASSWORD_LENGTH:
            raise UserValidationError("Senha muito longa: maximo de 128 caracteres")
        if len(password) < 8:
            raise UserValidationError("Senha fraca: minimo de 8 caracteres")
        has_upper = re.search(r"[A-Z]", password) is not None
        has_lower = re.search(r"[a-z]", password) is not None
        has_number = re.search(r"\d", password) is not None
        has_special = re.search(r"[^A-Za-z0-9]", password) is not None
        if not (has_upper and has_lower and has_number and has_special):
            raise UserValidationError(
                "Senha fraca: inclua letra maiuscula, letra minuscula, numero e caractere especial"
            )

    def _validate_username(self, username: str) -> None:
        if not USERNAME_PATTERN.fullmatch(username):
            raise UserValidationError(
                "Username invalido: use apenas letras, numeros e espaco"
            )
