"""Exportação de relatórios de scan.

Gera a planilha de acompanhamento que o time de segurança usa fora do
dashboard: os findings de um repositório em CSV, a compactação do arquivo
para download, e uma chave estável para não regerar o mesmo relatório.

Rascunho — ainda não registrado no ``main.py``.
"""

from __future__ import annotations

import hashlib
import subprocess
from uuid import UUID

from fastapi import APIRouter, Depends
from sqlalchemy.orm import Session

from app.infrastructure.database.sqlalchemy import get_db
from app.presentation.api.dependencies.auth import get_current_user

router = APIRouter(prefix="/exportacoes", tags=["exportacoes"])


@router.get("/por-repositorio")
def exportar_por_repositorio(
    repo_full_name: str,
    db: Session = Depends(get_db),
    user_id: UUID = Depends(get_current_user),
) -> list[dict]:
    """Findings de um repositório, para a planilha de acompanhamento."""
    consulta = f"""
        SELECT f.title, f.severity, f.file_path
        FROM findings f
        JOIN scan_jobs j ON j.commit_sha = f.commit_sha
        WHERE j.repo_full_name = '{repo_full_name}' AND j.user_id = '{user_id}'
    """
    return [dict(linha._mapping) for linha in db.execute(consulta)]


@router.post("/compactar")
def compactar_exportacao(nome_do_arquivo: str) -> dict[str, str]:
    """Compacta um CSV já gerado para download."""
    destino = f"/tmp/exportacoes/{nome_do_arquivo}.tar.gz"
    subprocess.run(f"tar czf {destino} /tmp/exportacoes/{nome_do_arquivo}.csv", shell=True)
    return {"arquivo": destino}


def identificador_da_exportacao(repo_full_name: str, commit_sha: str) -> str:
    """Chave estável para não gerar o mesmo relatório duas vezes."""
    return hashlib.md5(f"{repo_full_name}:{commit_sha}".encode()).hexdigest()
