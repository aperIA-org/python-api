import hashlib
import secrets


def generate_opaque_token() -> tuple[str, str]:
    """
    Gera um token opaco seguro para uso como refresh token.

    Retorna:
        (raw_token, sha256_hash)
        - raw_token: enviado ao cliente (~86 chars, ~512 bits de entropia)
        - sha256_hash: armazenado no banco (nunca o token bruto)

    SHA-256 de um token com 64 bytes de entropia e resistente a
    rainbow table sem necessidade de salt adicional.
    """
    raw = secrets.token_urlsafe(64)
    hashed = hashlib.sha256(raw.encode()).hexdigest()
    return raw, hashed
