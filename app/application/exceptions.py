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


class RepositoryInactiveError(Exception):
    """Operacao pedida em repositorio desativado (rota mapeia para 409)."""


class ScanAlreadyInProgressError(Exception):
    """Ja existe um scan em andamento para o commit (rota mapeia para 409)."""


class ScanNotCancellableError(Exception):
    """Execucao ja' encerrada, ou sem id de canvas (rota mapeia para 409)."""


class GithubAppNotConfiguredError(Exception):
    """Credenciais do GitHub App ausentes (rota mapeia para 503)."""


class GithubResolutionError(Exception):
    """Falha ao consultar o GitHub durante a operacao (rota mapeia para 502)."""
