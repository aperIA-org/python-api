"""MITRE Caldera client — emulação de adversários em sandbox.

INVIOLÁVEL: ``CALDERA_SANDBOX_MODE`` é validado no ``__init__``.
Se ``False``, ``SandboxViolationError`` é levantado ANTES de
qualquer cliente HTTP ser construído. Caldera executa técnicas
MITRE ATT&CK reais — sem isolamento de rede, movimento lateral
pode escapar.

Pipeline ``run_safe`` (top-level):
    1. create_adversary(name, ttps) → adversary_id
    2. run_operation(adversary_id) → operation_id
    3. await_results(operation_id) → dict com success_rate

Diferente de ``BaseScanner.run_safe``, este wrapper retorna um
**dict de status** (não ``list[Finding]``) — Caldera produz
métricas de emulação, não findings. Qualquer falha vira
``{"status": "failed", "reason": …, "caldera_validated": False,
"success_rate": 0.0, ...}`` (decisão #1 Semana 10).

``POLL_INTERVAL`` vem de ``settings.CALDERA_POLL_INTERVAL``;
testes injetam ``poll_interval=0`` no construtor.
``MAX_WAIT`` é fixo em 600s — não negociável.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field

import time
from typing import Any

import httpx
import structlog

from app.config import settings
from app.core.exceptions import SandboxViolationError

logger = structlog.get_logger()


# Facts cujo namespace é de serviço externo: exigem credencial que o sandbox
# isolado não tem (e não deve ter). Denylist e não allowlist de propósito — uma
# ability nova de enumeração local deve continuar entrando sem precisar de
# cadastro; uma nova de exfiltração para provedor X será notada quando aparecer.
_NAMESPACES_EXTERNOS = frozenset(
    {"dropbox", "github", "aws", "s3", "azure", "gcp", "slack", "twitter", "smtp", "ftp"}
)

# Marcas de credencial em qualquer namespace.
_MARCAS_DE_CREDENCIAL = ("api.key", "access.token", "secret", "password", "passwd")


@dataclass
class MapeamentoAbilities:
    """O que sobrou depois de traduzir técnicas MITRE em abilities do Caldera.

    Não basta a lista de abilities: é preciso saber **como** cada uma foi
    encontrada. Uma ability achada porque a sub-técnica pedida existe no
    catálogo valida o achado; uma achada por fallback para a técnica-pai valida
    algo *relacionado* — `T1059.001` (PowerShell) quando o achado é `T1059.007`
    (JavaScript) é a mesma família, não o mesmo ataque. Tratar as duas como
    iguais transformaria "emulei um primo do seu problema" em
    `caldera_validated: true`.
    """

    abilities: list[str] = field(default_factory=list)
    #: technique_ids do CATÁLOGO que casaram exatamente com o que foi pedido.
    tids_exatos: set[str] = field(default_factory=set)
    #: technique_ids do catálogo que só entraram via fallback de pai.
    tids_por_pai: set[str] = field(default_factory=set)
    #: técnicas PEDIDAS que só foram cobertas truncando para o pai.
    pedidas_por_pai: list[str] = field(default_factory=list)
    #: técnicas pedidas sem nenhuma ability, nem após o fallback.
    pedidas_sem_cobertura: list[str] = field(default_factory=list)
    descartadas: int = 0
    #: descartadas por implantarem outro agente (ver `_implanta_agente`).
    implantam_agente: int = 0


class CalderaClient:
    """Wrapper sobre a REST API do Caldera v2."""

    MAX_WAIT: int = 600  # não negociável — decisão #1 Semana 10

    def __init__(
        self,
        *,
        base_url: str | None = None,
        poll_interval: int | None = None,
        http_client: httpx.Client | None = None,
    ) -> None:
        # Sandbox check ANTES de qualquer outra coisa. Se cair aqui
        # e alguém propagar o erro, garante que nenhum agente foi
        # contatado.
        if not settings.CALDERA_SANDBOX_MODE:
            raise SandboxViolationError(
                "CALDERA_SANDBOX_MODE está desabilitado. "
                "Caldera só pode executar em sandbox."
            )
        self.poll_interval = (
            poll_interval
            if poll_interval is not None
            else settings.CALDERA_POLL_INTERVAL
        )
        self.client = http_client or httpx.Client(
            # No deploy AWS a URL é a da task Fargate daquele scan, não a fixa.
            base_url=base_url or settings.CALDERA_URL,
            headers={"KEY": settings.CALDERA_API_KEY},
            timeout=30.0,
        )

    # ------------------------------------------------------------------ API

    def create_adversary(
        self,
        name: str,
        mitre_techniques: list[str],
        has_verified_secrets: bool = False,
        *,
        mapeamento: MapeamentoAbilities | None = None,
    ) -> str:
        """Cria o adversário. `mapeamento` evita mapear duas vezes quando o
        `run_safe` já precisou do detalhe para classificar a validação."""
        mapa = mapeamento or self._map_to_abilities(mitre_techniques)
        abilities = mapa.abilities
        resp = self.client.post(
            "/api/v2/adversaries",
            json={
                "name": f"aperia-{name}",
                "description": "Auto-generated by aperIA — sandbox only",
                "atomic_ordering": abilities,
            },
        )
        resp.raise_for_status()
        # A API v2 devolve `adversary_id`, NÃO `id` — ler `id` aqui levantava
        # `KeyError: 'id'` logo após um POST bem-sucedido (200), e o
        # `run_safe` traduzia para "Caldera unavailable". O erro parecia de
        # conectividade quando a chamada tinha funcionado.
        return resp.json()["adversary_id"]

    def run_operation(self, adversary_id: str) -> str:
        # Antes de disparar: quantos alvos esse grupo tem, afinal? Ver o
        # docstring de `_registrar_agentes_do_grupo` — é diagnóstico, nunca
        # bloqueia a operação.
        self._registrar_agentes_do_grupo(settings.CALDERA_AGENT_GROUP)
        resp = self.client.post(
            "/api/v2/operations",
            json={
                "name": f"aperia-op-{adversary_id[:8]}",
                # Mesma assimetria: o adversário é referenciado por
                # `adversary_id`; a operação é que devolve `id`.
                "adversary": {"adversary_id": adversary_id},
                "planner": {"id": "atomic"},
                "group": settings.CALDERA_AGENT_GROUP,
            },
        )
        resp.raise_for_status()
        return resp.json()["id"]

    def await_results(
        self, operation_id: str, mapeamento: MapeamentoAbilities | None = None
    ) -> dict[str, Any]:
        # Bound de iterações; cada loop espera ``poll_interval``
        # segundos (0 nos testes para evitar sleep real).
        iterations = max(self.MAX_WAIT // max(self.poll_interval, 1), 1)
        for _ in range(iterations):
            resp = self.client.get(f"/api/v2/operations/{operation_id}")
            resp.raise_for_status()
            op = resp.json()
            if op.get("state") == "finished":
                return self._parse_results(op, mapeamento)
            if self.poll_interval > 0:
                time.sleep(self.poll_interval)
        raise TimeoutError(
            f"Caldera operation {operation_id} não finalizou em "
            f"{self.MAX_WAIT}s"
        )

    # ------------------------------------------------------- run_safe wrapper

    def run_safe(
        self,
        adversary_name: str,
        mitre_techniques: list[str],
        has_verified_secrets: bool = False,
    ) -> dict[str, Any]:
        """Orquestra todo o pipeline Caldera, isolando falhas.

        Retorna sempre um dict (decisão #1):

        - alcançado: ``{"status": "reachable", "success_rate": …, "ttps_used": …,
          "caldera_validated": bool, "validacao_parcial": bool, …}``

        ``status`` responde **"o Caldera respondeu?"**, não "a emulação
        validou?". Era ``"ok"``, e isso se lia como sucesso mesmo em resultados
        com ``0/0 técnicas executadas`` — quem valida é ``caldera_validated``.
        - falha:   ``{"status": "failed", "reason": "…",
          "caldera_validated": False, "success_rate": 0.0,
          "techniques_executed": 0, "techniques_successful": 0,
          "ttps_used": []}``
        """
        try:
            mapa = self._map_to_abilities(mitre_techniques)
            adversary_id = self.create_adversary(
                adversary_name,
                mitre_techniques,
                has_verified_secrets,
                mapeamento=mapa,
            )
            operation_id = self.run_operation(adversary_id)
            results = self.await_results(operation_id, mapa)
            results.setdefault("status", "reachable")
            return results
        except TimeoutError as exc:
            logger.warning(
                "caldera_timeout",
                adversary=adversary_name,
                techniques=mitre_techniques,
                error=str(exc),
            )
            return _failed_result("timeout")
        except Exception as exc:  # noqa: BLE001 — fault isolation total
            logger.warning(
                "caldera_run_safe_failed",
                adversary=adversary_name,
                techniques=mitre_techniques,
                error=str(exc),
                error_type=type(exc).__name__,
            )
            return _failed_result(type(exc).__name__)

    # -------------------------------------------------------- internals

    #: O sandbox tem UM container de agente (`caldera-agent` no compose), logo
    #: um grupo saudável tem exatamente um agente. Ver `_registrar_agentes_do_grupo`.
    AGENTES_ESPERADOS: int = 1

    def _registrar_agentes_do_grupo(self, grupo: str) -> int | None:
        """Loga quantos agentes o grupo tem ANTES de criar a operação.

        Uma operação do Caldera executa cada ability em **todos** os agentes do
        grupo. Com N agentes o trabalho é N×, a técnica MITRE real roda N vezes,
        e o ``success_rate`` sai calculado sobre uma amostra inflada que não
        corresponde a alvo nenhum. Aconteceu de verdade: o serviço do agente
        reiniciava e registrava um agente novo a cada vez, chegando a 20 — e o
        número não aparecia em log algum, então o problema só apareceu quando
        alguém foi investigar outra coisa. Este log é o que torna esse sintoma
        visível na próxima vez.

        Filtro local, uma requisição só — mesmo motivo de ``_map_to_abilities``:
        a lista de agentes é pequena e a API v2 cobra um formato de query
        próprio para filtrar.

        Best-effort como o resto do cliente: falha aqui devolve ``None`` e a
        operação segue. Diagnóstico não pode derrubar o pipeline.
        """
        try:
            resp = self.client.get("/api/v2/agents")
            resp.raise_for_status()
            agentes = resp.json() or []
        except Exception as exc:  # noqa: BLE001 — best-effort, só diagnóstico
            logger.warning("caldera_contagem_de_agentes_falhou", error=str(exc))
            return None

        do_grupo = [
            a
            for a in agentes
            if isinstance(a, dict) and str(a.get("group") or "") == grupo
        ]
        paws = [str(a.get("paw") or "") for a in do_grupo]
        total = len(do_grupo)

        evento = logger.info if total == self.AGENTES_ESPERADOS else logger.warning
        evento(
            "caldera_agentes_do_grupo",
            grupo=grupo,
            agentes=total,
            esperados=self.AGENTES_ESPERADOS,
            # A lista inteira, não uma amostra: com PAW fixo ela tem um item, e
            # quando não tiver, os PAWs são exatamente o que se precisa para
            # saber quais remover.
            paws=paws,
            confiavel=sum(1 for a in do_grupo if a.get("trusted")),
        )
        return total

    def _map_to_abilities(self, techniques: list[str]) -> MapeamentoAbilities:
        """Traduz TTPs MITRE (``T1059``) em abilities do Caldera.

        Era um stub que devolvia ``[]``, e o efeito passava despercebido: o
        adversário nascia **sem nenhuma ability**, a operação terminava com
        cadeia vazia e ``caldera_validated`` era sempre ``False``. Parecia
        "emulação não encontrou nada" quando nada foi executado — a mesma
        confusão entre "não achei" e "não procurei" que já apareceu no Tier 1.

        **Uma requisição, filtro local.** A API v2 não filtra por técnica:
        ``GET /api/v2/abilities?technique_id=T1082`` responde **422**. O
        catálogo inteiro são ~162 abilities, então buscar tudo uma vez e casar
        aqui é mais simples e mais barato que N requisições.

        **Duas passadas, e a segunda é rotulada.** A primeira casa exatamente:
        pedir ``T1497`` pega todas as filhas, pedir ``T1497.003`` pega só ela.
        Uma sub-técnica que não sobrou de lá tenta de novo pelo **pai** — foi o
        que um scan real expôs: o Tier 2 pediu ``T1059.007``/``T1552.001`` e o
        catálogo só tem ``T1059.001/.002/.004`` e ``T1552.002/.003/.004``, então
        7 técnicas viravam 0 abilities. Truncar para o pai leva a 3.

        O resultado dessa segunda passada **não vale como validação do achado**:
        é a mesma família, outro ataque. Por isso os dois conjuntos voltam
        separados, e é ``_parse_results`` quem decide o que conta.

        Só entram abilities com executor **linux**: o agente do sandbox roda
        Linux, e ability de Windows na cadeia vira link que falha, derrubando o
        ``success_rate`` por motivo que não é do alvo.
        """
        if not techniques:
            return MapeamentoAbilities()

        pedidas = {
            str(t or "").strip().upper() for t in techniques if str(t or "").strip()
        }
        if not pedidas:
            return MapeamentoAbilities()

        try:
            resp = self.client.get("/api/v2/abilities")
            resp.raise_for_status()
            catalogo = resp.json() or []
        except Exception as exc:  # noqa: BLE001 — best-effort, como o resto
            logger.warning("caldera_ability_lookup_failed", error=str(exc))
            return MapeamentoAbilities()

        mapa = MapeamentoAbilities()
        # Chaveado por ability_id: a passada exata e a do fallback avaliam a
        # mesma ability, e contar duas vezes inflava o diagnóstico.
        descartadas: dict[str, str] = {}
        implantadoras: dict[str, str] = {}

        # --- 1a passada: casamento exato -----------------------------------
        cobertas = self._coletar(
            catalogo, pedidas, mapa, descartadas, implantadoras, exato=True
        )

        # --- 2a passada: fallback para o pai, só do que ficou descoberto ----
        descobertas = pedidas - cobertas
        pais = {
            t.split(".", 1)[0]
            for t in descobertas
            if "." in t and t.split(".", 1)[0] not in pedidas
        }
        if pais:
            cobertos_por_pai = self._coletar(
                catalogo, pais, mapa, descartadas, implantadoras, exato=False
            )
            mapa.pedidas_por_pai = sorted(
                t for t in descobertas if t.split(".", 1)[0] in cobertos_por_pai
            )

        mapa.pedidas_sem_cobertura = sorted(
            descobertas - set(mapa.pedidas_por_pai)
        )
        mapa.descartadas = len(descartadas)
        mapa.implantam_agente = len(implantadoras)

        # `descartadas` distingue "a técnica não existe no catálogo" de "existe,
        # mas não roda aqui"; `por_pai` distingue as duas de "existe algo da
        # família, mas não o que foi pedido".
        logger.info(
            "caldera_abilities_mapeadas",
            tecnicas=len(pedidas),
            abilities=len(mapa.abilities),
            exatas=len(mapa.tids_exatos),
            por_pai=len(mapa.tids_por_pai),
            pedidas_por_pai=mapa.pedidas_por_pai[:3],
            sem_cobertura=mapa.pedidas_sem_cobertura[:3],
            descartadas=mapa.descartadas,
            implantam_agente=mapa.implantam_agente,
            exemplos_descartados=list(descartadas.values())[:3],
            exemplos_implantadoras=list(implantadoras.values())[:3],
            catalogo=len(catalogo),
        )
        return mapa

    def _coletar(
        self,
        catalogo: list,
        alvos: set[str],
        mapa: MapeamentoAbilities,
        descartadas: dict[str, str],
        implantadoras: dict[str, str],
        *,
        exato: bool,
    ) -> set[str]:
        """Acrescenta a `mapa` as abilities que casam com `alvos`.

        Devolve quais `alvos` chegaram a produzir alguma ability — é isso que
        diz o que ainda está descoberto e precisa do fallback.
        """
        cobertos: set[str] = set()
        for ability in catalogo:
            if not isinstance(ability, dict):
                continue
            tid = str(ability.get("technique_id") or "").upper()
            if not tid or not self._casa_tecnica(tid, alvos):
                continue
            if not self._tem_executor_linux(ability):
                continue
            ability_id = ability.get("ability_id") or ability.get("id")
            if not ability_id or ability_id in mapa.abilities:
                continue
            if self._implanta_agente(ability):
                # Antes do filtro de credencial: esta é a que causa laço.
                if ability_id not in implantadoras:
                    implantadoras[ability_id] = ability.get("name") or ability_id
                    logger.warning(
                        "caldera_ability_implanta_agente_descartada",
                        ability=implantadoras[ability_id],
                        technique_id=tid,
                    )
                continue
            if not self._executavel_no_sandbox(ability):
                descartadas[ability_id] = ability.get("name") or ability_id
                continue
            mapa.abilities.append(ability_id)
            (mapa.tids_exatos if exato else mapa.tids_por_pai).add(tid)
            cobertos.add(tid if tid in alvos else tid.split(".", 1)[0])
        return cobertos

    #: O binário do agente do Caldera. `54ndc47` é como o Stockpile escreve
    #: "sandcat" — as duas grafias aparecem em comando e em payload.
    _MARCADOR_AGENTE = re.compile(r"sandcat|54ndc47", re.I)

    @classmethod
    def _implanta_agente(cls, ability: dict[str, Any]) -> bool:
        """`True` se a ability inicia/instala outro agente do Caldera.

        **Incidente real (2026-08-02).** Uma operação pediu `T1059.007`; o
        fallback de pai trouxe `T1059.004` → **"Start 54ndc47"**, cujo comando é
        `nohup ./sandcat.go -server ... &`. Como uma operação executa cada
        ability em **todos** os agentes do grupo, cada execução criava um agente
        que entrava no grupo e recebia a mesma ability. Em 10 minutos foram 20
        agentes e 43 elos, a operação nunca terminou (timeout de 600s) e a
        máquina do dev pagou a conta.

        Isso também explica melhor os "20 agentes acumulados" que antes foram
        atribuídos só ao `restart: unless-stopped` do container: fixar o PAW
        resolve o reinício, não este laço.

        São 5 abilities linux de 70 no catálogo padrão, todas de implantação:
        `Start 54ndc47`, `Start 54ndc47 (2)`, `Sandcat`, `Copy 54ndc47` e
        `Weak executable files` — esta última escreve um lançador do agente em
        todo executável gravável que encontra.

        Emular implantação de agente não diz nada sobre o achado do scan: o que
        ela prova é que o Caldera consegue instalar o Caldera.
        """
        for executor in ability.get("executors", []) or []:
            if str(executor.get("platform", "")).lower() != "linux":
                continue
            alvo = " ".join(
                [str(executor.get("command") or "")]
                + [str(p) for p in (executor.get("payloads") or [])]
            )
            if cls._MARCADOR_AGENTE.search(alvo):
                return True
        return False

    @staticmethod
    def _facts_exigidos(ability: dict[str, Any]) -> set[str]:
        """Facts que os executores linux da ability referenciam (`#{fato}`)."""
        facts: set[str] = set()
        for executor in ability.get("executors", []) or []:
            if str(executor.get("platform", "")).lower() != "linux":
                continue
            facts.update(re.findall(r"#\{([a-zA-Z0-9._]+)\}", executor.get("command", "") or ""))
        return facts

    @classmethod
    def _executavel_no_sandbox(cls, ability: dict[str, Any]) -> bool:
        """`False` se a ability depende de credencial de serviço externo.

        O sandbox do Caldera é `internal: true` — sem rota para a internet, por
        desenho: é o único mecanismo que impede movimento lateral de teste
        alcançar sistema real. Abilities de exfiltração para Dropbox, GitHub ou
        S3 exigem `dropbox.api.key`, `github.access.token` e afins, que nós não
        temos nem devemos fornecer.

        Sem elas satisfeitas o planner atômico não gera elo NENHUM e encerra a
        operação na hora — foi o que aconteceu: 6 abilities mapeadas, 0
        executadas, e o relatório dizendo apenas `caldera_validated: false` sem
        explicar por quê.

        Descartar aqui é melhor que deixar o planner descartar: evita criar um
        adversário que provadamente não roda, e permite dizer no log o motivo.
        """
        for fact in cls._facts_exigidos(ability):
            namespace = fact.split(".", 1)[0].lower()
            if namespace in _NAMESPACES_EXTERNOS:
                return False
            if any(marca in fact.lower() for marca in _MARCAS_DE_CREDENCIAL):
                return False
        return True

    @staticmethod
    def _casa_tecnica(technique_id: str, pedidas: set[str]) -> bool:
        """`T1497.003` casa com `T1497.003` e também com o pai `T1497`."""
        if technique_id in pedidas:
            return True
        pai = technique_id.split(".", 1)[0]
        return pai in pedidas

    @staticmethod
    def _tem_executor_linux(ability: dict[str, Any]) -> bool:
        """`True` se a ability tem executor para Linux (plataforma do agente)."""
        for executor in ability.get("executors", []) or []:
            if not isinstance(executor, dict):
                continue
            if str(executor.get("platform", "")).lower() == "linux":
                return True
        return False

    def _parse_results(
        self, op: dict[str, Any], mapeamento: MapeamentoAbilities | None = None
    ) -> dict[str, Any]:
        links = op.get("chain", []) or []
        successful = [link for link in links if link.get("status") == 0]

        def tid_do(link: dict[str, Any]) -> str:
            return str((link.get("ability", {}) or {}).get("technique_id") or "").upper()

        # Sem mapeamento (chamada direta em teste), tudo conta como exato — é o
        # comportamento antigo. Com mapeamento, só valida o que casou com a
        # técnica PEDIDA: um sucesso vindo do fallback de pai emulou a família,
        # não o achado, e não pode virar `caldera_validated: true`.
        if mapeamento is None or not mapeamento.tids_por_pai:
            exatos = successful
        else:
            exatos = [
                link for link in successful if tid_do(link) in mapeamento.tids_exatos
            ]
        parciais = [link for link in successful if link not in exatos]

        return {
            "techniques_executed": len(links),
            "techniques_successful": len(successful),
            "success_rate": (len(successful) / len(links)) if links else 0.0,
            "ttps_used": [tid_do(link) or None for link in links],
            "caldera_validated": len(exatos) > 0,
            # Emulou algo da mesma família da técnica pedida, mas não ela.
            "validacao_parcial": len(exatos) == 0 and len(parciais) > 0,
            "tecnicas_por_pai": list(mapeamento.pedidas_por_pai) if mapeamento else [],
            "tecnicas_sem_cobertura": (
                list(mapeamento.pedidas_sem_cobertura) if mapeamento else []
            ),
        }


def _failed_result(reason: str) -> dict[str, Any]:
    return {
        "status": "failed",
        "reason": reason,
        "success_rate": 0.0,
        "techniques_executed": 0,
        "techniques_successful": 0,
        "ttps_used": [],
        "caldera_validated": False,
        "validacao_parcial": False,
        "tecnicas_por_pai": [],
        "tecnicas_sem_cobertura": [],
    }
