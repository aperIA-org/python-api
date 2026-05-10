from fastapi import APIRouter

router = APIRouter()


@router.get("/")
async def list_reports() -> dict:
    # DEBT: implementar na Fase 3
    return {"reports": []}
