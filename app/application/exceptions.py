class UserValidationError(Exception):
    pass


class InvalidCredentialsError(Exception):
    """Email ou senha invalidos. Mensagem intencionalmente generica."""


class TokenExpiredError(Exception):
    """O token (access ou refresh) esta expirado."""


class TokenRevokedError(Exception):
    """O token foi explicitamente revogado (logout ou expiracao)."""


class TokenReusedError(Exception):
    """
    Reuso de refresh token detectado.
    Indica possivel comprometimento - toda a familia deve ser revogada.
    """
