"""Remove agentes órfãos do Caldera (os que pararam de fazer beacon).

POR QUE EXISTE: até a correção do `-paw` fixo (ver `docker-compose.scanners.yml`,
serviço `caldera-agent`), cada reinício do container do agente registrava um
agente NOVO no Caldera. Restou uma coleção de agentes mortos no grupo `red` — e
isso não é só sujeira de listagem: uma operação executa cada ability em **todos**
os agentes do grupo, multiplicando a execução de técnicas MITRE reais e
calculando `success_rate` sobre uma amostra que não corresponde a alvo nenhum.

O `-paw` fixo impede que o problema volte; este script limpa o que já existe.

POR QUE MANUAL, E NÃO AUTOMÁTICO NO BOOT: deletar agente exige a chave de API do
Caldera. Colocá-la dentro do container do agente daria credencial de red team ao
container que existe justamente para ser atacado — exatamente o que o isolamento
de rede tenta evitar. Então a limpeza roda do host, sob decisão de quem opera.

POR QUE NÃO O `untrusted_timer` DO CALDERA: ele vive em `conf/agents.yml` (não em
`conf/local.yml`, que é o nosso) e não apaga nada — só marca o agente como
`untrusted` depois de N segundos em silêncio, o que impede novos elos mas deixa o
registro na lista para sempre.

CRITÉRIO: um agente vivo faz beacon a cada 30–60s (`sleep_min`/`sleep_max` do
Caldera). Quem não é visto há `--max-idade` segundos não vai voltar — o container
que o registrou já não existe. Agente sem `last_seen` legível NUNCA é removido:
na dúvida, o script não apaga.

Uso (o Caldera precisa estar no ar; a porta 8888 é publicada no host):

    .venv/bin/python scripts/caldera_limpar_agentes.py --dry-run
    .venv/bin/python scripts/caldera_limpar_agentes.py
"""

from __future__ import annotations

import argparse
import sys
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

import httpx

# Garante que a raiz do projeto esteja no sys.path ao rodar como script.
_ROOT = Path(__file__).resolve().parents[1]
if str(_ROOT) not in sys.path:
    sys.path.insert(0, str(_ROOT))

from app.config import settings  # noqa: E402  (import após ajuste do sys.path)

# `CALDERA_URL` aponta para `http://caldera:8888`, nome que só resolve DENTRO da
# rede do compose. Este script roda no host, onde o mesmo servidor é a porta
# publicada — daí o default divergir da config em vez de reusá-la.
URL_PADRAO = "http://localhost:8888"

# 5 minutos ≈ 5 a 10 beacons perdidos. Folgado o bastante para não apagar um
# agente que só está lento, curto o bastante para não exigir espera.
MAX_IDADE_PADRAO_S = 300


def parse_last_seen(valor: Any) -> datetime | None:
    """Converte o `last_seen` da API v2 em datetime aware, ou `None`.

    O Caldera devolve `2026-08-02T05:20:34Z`; `fromisoformat` do Python 3.10
    não aceita o sufixo `Z`, daí a troca por `+00:00`.
    """
    if not isinstance(valor, str) or not valor.strip():
        return None
    try:
        dt = datetime.fromisoformat(valor.strip().replace("Z", "+00:00"))
    except ValueError:
        return None
    return dt if dt.tzinfo else dt.replace(tzinfo=timezone.utc)


def agentes_obsoletos(
    agentes: list[dict[str, Any]],
    *,
    agora: datetime,
    max_idade_s: int = MAX_IDADE_PADRAO_S,
    manter_paws: frozenset[str] = frozenset(),
) -> list[dict[str, Any]]:
    """Agentes silenciosos há mais de `max_idade_s` segundos.

    Conservador de propósito: sem `last_seen` legível, o agente FICA. Apagar o
    agente errado significa uma operação sem alvo, e o custo de deixar um
    registro a mais é só cosmético até a próxima rodada do script.
    """
    obsoletos = []
    for agente in agentes:
        if not isinstance(agente, dict):
            continue
        paw = str(agente.get("paw") or "")
        if not paw or paw in manter_paws:
            continue
        visto = parse_last_seen(agente.get("last_seen"))
        if visto is None:
            continue
        if (agora - visto).total_seconds() > max_idade_s:
            obsoletos.append(agente)
    return obsoletos


def _cli() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--url", default=URL_PADRAO, help=f"padrão: {URL_PADRAO}")
    parser.add_argument("--key", default=settings.CALDERA_API_KEY)
    parser.add_argument("--max-idade", type=int, default=MAX_IDADE_PADRAO_S)
    parser.add_argument(
        "--manter",
        default="",
        help="PAWs a preservar mesmo se obsoletos, separados por vírgula",
    )
    parser.add_argument("--dry-run", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = _cli()
    manter = frozenset(p.strip() for p in args.manter.split(",") if p.strip())

    with httpx.Client(base_url=args.url, headers={"KEY": args.key}, timeout=30.0) as client:
        resp = client.get("/api/v2/agents")
        resp.raise_for_status()
        agentes = resp.json() or []

        agora = datetime.now(timezone.utc)
        alvos = agentes_obsoletos(
            agentes, agora=agora, max_idade_s=args.max_idade, manter_paws=manter
        )
        print(f"{len(agentes)} agente(s) registrado(s); {len(alvos)} obsoleto(s).")

        for agente in alvos:
            paw = agente["paw"]
            if args.dry_run:
                print(f"  [dry-run] removeria {paw} (visto em {agente.get('last_seen')})")
                continue
            r = client.delete(f"/api/v2/agents/{paw}")
            estado = "removido" if r.is_success else f"FALHOU ({r.status_code})"
            print(f"  {paw}: {estado}")

        restantes = len(agentes) - (0 if args.dry_run else len(alvos))
        print(f"restam {restantes} agente(s).")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
