from __future__ import annotations

from fastapi import APIRouter

router = APIRouter()


@router.get(
    "/health",
    tags=["health"],
    summary="Healthcheck",
    response_description="Serviço no ar.",
    responses={200: {"content": {"application/json": {"example": {"status": "ok"}}}}},
)
def health() -> dict[str, str]:
    """
    Retorna o estado de disponibilidade do serviço.

    Usado por orquestradores/load balancers. Não verifica dependências
    externas (banco, Redis) — responde `200` enquanto o processo estiver vivo.
    """
    return {"status": "ok"}
