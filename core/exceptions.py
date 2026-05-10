class AperIAError(Exception):
    """Base — nunca instanciar diretamente."""


class ScannerError(AperIAError):
    """Erro em ferramenta de scan externa."""


class ScannerTimeoutError(ScannerError):
    """Timeout na execução de scanner externo."""


class ScannerParseError(ScannerError):
    """Falha ao parsear output de scanner."""


class PromptInjectionError(AperIAError):
    """LLM Guard detectou tentativa de injection."""


class SandboxViolationError(AperIAError):
    """Tentativa de executar Caldera fora do sandbox."""


class InvalidWebhookSignature(AperIAError):
    """Assinatura HMAC inválida no webhook."""


class FindingNormalizationError(AperIAError):
    """Erro ao normalizar output de scanner."""


class RemediationError(AperIAError):
    """Erro na geração ou entrega de remediação."""


class CTIEnrichmentError(AperIAError):
    """Erro ao enriquecer finding via OpenCTI."""


class GitHubClientError(AperIAError):
    """Erro na comunicação com GitHub API."""


class PatchDeliveryError(AperIAError):
    """Erro ao entregar code suggestion no PR."""


class ScanJobNotFoundError(AperIAError):
    """ScanJob não encontrado no repositório."""


class DuplicateScanError(AperIAError):
    """Scan já em execução para o mesmo commit."""
