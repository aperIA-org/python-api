"""Limite de tentativas por IP, em janela fixa no Redis.

Usa o Redis que já existe para o Celery — ``INCR`` + ``EXPIRE`` é o suficiente
aqui e dispensa uma dependência nova.

Vale para os endpoints não autenticados: sem ele, cadastro e login aceitam
quantas tentativas o atacante quiser, o que transforma diferenças de resposta
em coleta em massa e deixa a senha aberta a força bruta.

``fail-open`` de propósito: se o Redis estiver fora, a requisição passa e fica
o log. Derrubar o login porque o contador caiu trocaria um problema de abuso
por uma indisponibilidade — e o Redis aqui é local, então se ele caiu a
aplicação já está degradada por outros motivos.
"""
from __future__ import annotations

import redis
import structlog
from fastapi import HTTPException, Request

from app.config import settings

logger = structlog.get_logger()

_cliente: redis.Redis | None = None


def _redis() -> redis.Redis:
    global _cliente
    if _cliente is None:
        _cliente = redis.Redis.from_url(settings.REDIS_URL, socket_timeout=1)
    return _cliente


def ip_do_cliente(request: Request) -> str:
    """IP real do cliente, considerando o proxy.

    Atrás do Caddy, ``request.client.host`` é o IP do container do proxy — o
    mesmo para todo mundo, o que faria um único contador para o mundo inteiro.

    Cada proxy **acrescenta** ao ``X-Forwarded-For`` o IP de quem conectou
    nele, então o último item foi escrito pelo proxy imediato e é o único
    confiável: os anteriores vieram do cliente e podem ser forjados para
    escapar do limite.
    """
    encaminhado = request.headers.get("x-forwarded-for")
    if encaminhado:
        return encaminhado.split(",")[-1].strip()
    return request.client.host if request.client else "desconhecido"


def limitar(request: Request, *, escopo: str, maximo: int, janela_s: int) -> None:
    ip = ip_do_cliente(request)
    chave = f"ratelimit:{escopo}:{ip}"
    try:
        r = _redis()
        atual = r.incr(chave)
        if atual == 1:
            r.expire(chave, janela_s)
    except redis.RedisError as exc:
        logger.warning("rate_limit_indisponivel", escopo=escopo, error=str(exc))
        return

    if atual > maximo:
        logger.warning("rate_limit_excedido", escopo=escopo, ip=ip, tentativas=atual)
        raise HTTPException(
            status_code=429,
            detail="Muitas tentativas. Tente novamente mais tarde.",
            headers={"Retry-After": str(janela_s)},
        )


def limite_por_ip(*, escopo: str, maximo: int, janela_s: int):
    """Dependency do FastAPI: ``Depends(limite_por_ip(...))``."""

    def dependency(request: Request) -> None:
        limitar(request, escopo=escopo, maximo=maximo, janela_s=janela_s)

    return dependency
