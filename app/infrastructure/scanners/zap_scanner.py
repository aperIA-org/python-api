"""ZAP — DAST ativo via REST API.

Pipeline:
    handshake() → confirma que o daemon está vivo ANTES de começar
    aplicar_tetos() → limita duração de spider/ascan no lado do ZAP
    spider(target_url) → ativa o crawler do ZAP para mapear endpoints
    active_scan(target_url) → envia payloads reais (SQLi, XSS, CSRF, …)
    collect_alerts(target_url) → coleta findings e normaliza para ``Finding``

Por que ativo, não passivo: passivo só analisa tráfego capturado;
para um ASPM precisamos de evidência de exploração, então payloads
reais via active scan são obrigatórios.

Sandbox/preview: o ``target_url`` precisa apontar para um deploy
acessível (ex: preview do Render/Railway, container efêmero). Se não
houver target válido, ``run_safe()`` do ``BaseScanner`` absorve a
falha e retorna ``[]`` — pipeline continua.

**Os tetos vivem no ZAP, não só aqui.** Contra uma aplicação grande
(o OWASP Juice Shop tem centenas de rotas) o active scan não termina
sozinho em tempo de pipeline. Esperar mais só troca "sem resultado em
10 min" por "sem resultado em 40 min": quando o cliente desiste, o
scan é abandonado e os alertas já encontrados vão junto. Por isso o
scanner manda o ZAP se limitar (``setOptionMaxScanDurationInMins`` e
irmãos) — ele encerra sozinho, a fase chega a 100% e coletamos o que
deu tempo de achar. Cobertura parcial e visível vale mais que
cobertura total que nunca chega. Os tetos do cliente ficam **acima**
dos do ZAP: se o cliente estourar primeiro, o problema não é o alvo
ser grande, é o ZAP não estar respeitando o próprio limite.

``poll_interval`` e ``max_wait`` são configuráveis para testes
(``poll_interval=0`` evita ``time.sleep`` real).
"""
from __future__ import annotations

from urllib.parse import urlsplit

import time
from typing import Any

import httpx
import structlog

from app.config import settings
from app.core.exceptions import AperiaError, ScannerUnavailableError
from app.domain.finding.entities import Finding
from app.domain.finding.value_objects import Severity
from app.infrastructure.scanners.base_scanner import BaseScanner
from app.infrastructure.scanners.zap_fargate import zap_sob_demanda

logger = structlog.get_logger()


_RISK_MAP = {
    "High": Severity.HIGH,
    "Medium": Severity.MEDIUM,
    "Low": Severity.LOW,
    "Informational": Severity.INFO,
}

# Timeout de CADA request HTTP ao daemon. Era 30s e estourava: durante o
# active scan o ZAP prioriza as threads de ataque e a API demora a responder,
# então `httpx.ReadTimeout` (cuja mensagem é literalmente "timed out")
# derrubava um scan de vários minutos por causa de um único poll lento.
_HTTP_TIMEOUT_S = 60.0

# Folga entre o teto do ZAP e o teto do cliente. O ZAP não corta no
# milissegundo: ao bater `maxScanDurationInMins` ele ainda espera as regras em
# voo drenarem. Sem folga, o cliente desistiria de um scan que ia terminar.
_FOLGA_TETO_S = 120

# Quantos polls seguidos podem falhar por erro de transporte antes de
# declararmos o daemon morto. >1 tolera um blip; um número alto esconderia um
# container que morreu (OOM) atrás de minutos de silêncio.
_MAX_FALHAS_POLL = 3


class ZAPUnavailableError(ScannerUnavailableError):
    """O daemon do ZAP não respondeu: container morto (OOM), fora do ar ou DNS.

    Separada de ``ZAPScanTimeoutError`` porque as duas exigem ações opostas: a
    primeira é "conserte a infraestrutura", a segunda é "o alvo é grande
    demais para o teto". As duas viravam o mesmo ``scanner_skipped`` com
    mensagens do httpx — e uma delas ("No address associated with hostname",
    resultado do container já ter morrido) chegou a ser diagnosticada como
    problema de DNS.
    """


class ZAPScanTimeoutError(AperiaError):
    """O ZAP está vivo, mas a fase não chegou a 100% dentro do teto do cliente."""



def _caminho_da_url(url: str) -> str:
    """Caminho + query da URL do alerta, sem esquema nem host.

    O host é sempre o alvo do scan: repeti-lo em cada linha é ruído. A query
    entra porque o ZAP reporta alertas distintos para parâmetros distintos
    (`/search?q=` é outra superfície que `/search`).
    """
    if not url:
        return ""
    partes = urlsplit(url)
    caminho = partes.path or "/"
    if partes.query:
        caminho = f"{caminho}?{partes.query}"
    return caminho[:500]


def _nome_do_repo(repo_url: str) -> str:
    """`https://github.com/org/repo` → `repo`, igual aos outros scanners."""
    if not repo_url:
        return ""
    return (repo_url.rstrip("/").rsplit("/", 1)[-1] or "").removesuffix(".git")[:255]

class ZAPScanner(BaseScanner):
    # Pior caso das duas fases somadas, já com folga. Informativo: o controle
    # real é por fase, em `_poll_status`.
    TIMEOUT = 900

    def __init__(
        self,
        zap_url: str | None = None,
        api_key: str | None = None,
        poll_interval: int = 10,
        max_wait: int | None = None,
        http_client: httpx.Client | None = None,
        spider_max_duration_min: int | None = None,
        spider_max_children: int | None = None,
        ascan_max_duration_min: int | None = None,
        ascan_max_rule_duration_min: int | None = None,
        ascan_threads_per_host: int | None = None,
        ascan_disabled_rules: str | None = None,
    ) -> None:
        self.zap_url = (zap_url or settings.ZAP_BASE_URL).rstrip("/")
        self.api_key = api_key or settings.ZAP_API_KEY
        self.poll_interval = poll_interval
        self.client = http_client or httpx.Client(timeout=_HTTP_TIMEOUT_S)

        self.spider_max_duration_min = (
            settings.ZAP_SPIDER_MAX_DURATION_MIN
            if spider_max_duration_min is None
            else spider_max_duration_min
        )
        self.spider_max_children = (
            settings.ZAP_SPIDER_MAX_CHILDREN
            if spider_max_children is None
            else spider_max_children
        )
        self.ascan_max_duration_min = (
            settings.ZAP_ASCAN_MAX_DURATION_MIN
            if ascan_max_duration_min is None
            else ascan_max_duration_min
        )
        self.ascan_max_rule_duration_min = (
            settings.ZAP_ASCAN_MAX_RULE_DURATION_MIN
            if ascan_max_rule_duration_min is None
            else ascan_max_rule_duration_min
        )
        self.ascan_threads_per_host = (
            settings.ZAP_ASCAN_THREADS_PER_HOST
            if ascan_threads_per_host is None
            else ascan_threads_per_host
        )
        self.ascan_disabled_rules = (
            settings.ZAP_ASCAN_DISABLED_RULES
            if ascan_disabled_rules is None
            else ascan_disabled_rules
        ).strip()

        # `max_wait` explícito continua valendo como teto único das duas fases
        # (é assim que os testes fixam um limite curto). Sem ele, cada fase
        # ganha o teto do ZAP + folga, que é o que faz sentido em produção.
        self.max_wait = max_wait
        self.spider_max_wait = max_wait or (
            self.spider_max_duration_min * 60 + _FOLGA_TETO_S
        )
        self.ascan_max_wait = max_wait or (
            self.ascan_max_duration_min * 60 + _FOLGA_TETO_S
        )

    def scan(
        self,
        target_url: str,
        commit_sha: str,
        repo_url: str,
    ) -> list[Finding]:
        inicio = time.monotonic()
        # Na AWS o ZAP é uma task Fargate por scan; falha ao subir cai no
        # run_safe como qualquer outro erro do scanner.
        with zap_sob_demanda(self.zap_url) as zap_url:
            self.zap_url = zap_url
            self._handshake(commit_sha)
            self._aplicar_tetos(commit_sha)
            self._spider(target_url, commit_sha)
            self._active_scan(target_url, commit_sha)
            return self._collect_alerts(
                target_url,
                commit_sha,
                repo_url,
                duracao_s=int(time.monotonic() - inicio),
            )

    # ----- request helper -----

    def _get(self, path: str, params: dict[str, Any], *, fase: str) -> httpx.Response:
        """GET no daemon, traduzindo erro de transporte em ``ZAPUnavailableError``.

        Erro de transporte aqui é sempre "o daemon não está lá": DNS sem
        resposta, conexão recusada, socket morto no meio. Um 4xx/5xx é outra
        coisa (o ZAP respondeu) e segue como ``HTTPStatusError``.
        """
        try:
            resp = self.client.get(
                f"{self.zap_url}{path}", params={**params, "apikey": self.api_key}
            )
        except httpx.TransportError as e:
            raise ZAPUnavailableError(
                f"ZAP inacessível em {self.zap_url} (fase={fase}): "
                f"{type(e).__name__}: {e}"
            ) from e
        resp.raise_for_status()
        return resp

    def _handshake(self, commit_sha: str) -> None:
        """Confirma que o daemon está vivo antes de qualquer trabalho.

        Sem isso, um container morto só aparecia como falha do spider — e a
        mensagem do httpx sugeria o problema errado.
        """
        resp = self._get("/JSON/core/view/version/", {}, fase="handshake")
        logger.info(
            "zap_disponivel",
            commit_sha=commit_sha,
            zap_url=self.zap_url,
            versao=str(resp.json().get("version", "?")),
        )

    # ----- tetos aplicados no lado do ZAP -----

    def _aplicar_tetos(self, commit_sha: str) -> None:
        opcoes = (
            ("/JSON/spider/action/setOptionMaxDuration/", self.spider_max_duration_min),
            (
                "/JSON/ascan/action/setOptionMaxScanDurationInMins/",
                self.ascan_max_duration_min,
            ),
            (
                "/JSON/ascan/action/setOptionMaxRuleDurationInMins/",
                self.ascan_max_rule_duration_min,
            ),
            ("/JSON/ascan/action/setOptionThreadPerHost/", self.ascan_threads_per_host),
        )
        for path, valor in opcoes:
            if valor <= 0:  # 0 = "não limitar", semântica do próprio ZAP
                continue
            try:
                self._get(path, {"Integer": valor}, fase="config")
            except (ZAPUnavailableError, httpx.HTTPError) as e:
                # Best-effort: uma opção que esta versão do ZAP não conhece não
                # justifica abortar o scan — só perde o teto correspondente.
                logger.warning(
                    "zap_opcao_ignorada",
                    commit_sha=commit_sha,
                    opcao=path,
                    valor=valor,
                    error=str(e),
                )
        if self.ascan_disabled_rules:
            try:
                self._get(
                    "/JSON/ascan/action/disableScanners/",
                    {"ids": self.ascan_disabled_rules},
                    fase="config",
                )
            except (ZAPUnavailableError, httpx.HTTPError) as e:
                logger.warning(
                    "zap_opcao_ignorada",
                    commit_sha=commit_sha,
                    opcao="disableScanners",
                    valor=self.ascan_disabled_rules,
                    error=str(e),
                )
        logger.info(
            "zap_tetos_aplicados",
            commit_sha=commit_sha,
            spider_max_duration_min=self.spider_max_duration_min,
            spider_max_children=self.spider_max_children,
            ascan_max_duration_min=self.ascan_max_duration_min,
            ascan_max_rule_duration_min=self.ascan_max_rule_duration_min,
            ascan_threads_per_host=self.ascan_threads_per_host,
            ascan_disabled_rules=self.ascan_disabled_rules or "nenhuma",
        )

    # ----- spider / active scan -----

    def _spider(self, target_url: str, commit_sha: str = "") -> None:
        params: dict[str, Any] = {"url": target_url}
        if self.spider_max_children > 0:
            # Limita quantos filhos por nó o crawler expande. É o corte mais
            # barato numa aplicação com listagens grandes: sem ele o spider
            # gasta o orçamento inteiro enumerando itens de catálogo, que são
            # a mesma rota repetida.
            params["maxChildren"] = self.spider_max_children
        resp = self._get("/JSON/spider/action/scan/", params, fase="spider")
        scan_id = resp.json()["scan"]
        self._poll_status(
            "/JSON/spider/view/status/",
            scan_id,
            label="spider",
            max_wait=self.spider_max_wait,
            commit_sha=commit_sha,
        )

    def _active_scan(self, target_url: str, commit_sha: str = "") -> None:
        resp = self._get(
            "/JSON/ascan/action/scan/", {"url": target_url}, fase="ascan"
        )
        scan_id = resp.json()["scan"]
        self._poll_status(
            "/JSON/ascan/view/status/",
            scan_id,
            label="ascan",
            max_wait=self.ascan_max_wait,
            commit_sha=commit_sha,
        )

    def _poll_status(
        self,
        path: str,
        scan_id: str,
        label: str,
        max_wait: int | None = None,
        commit_sha: str = "",
    ) -> int:
        teto_s = max_wait if max_wait is not None else self.ascan_max_wait
        # Dois tetos independentes. O de TEMPO é o que vale em produção — o
        # anterior somava `poll_interval` a cada volta e ignorava a duração da
        # própria requisição, então um poll de 30s contava como 10s e o limite
        # real era muito maior que o declarado. O de POLLS existe porque em
        # teste `poll_interval=0` congela o relógio de parede: sem ele o laço
        # giraria milhares de vezes até o cronômetro andar.
        teto_polls = teto_s // max(self.poll_interval, 1) + 1
        inicio = time.monotonic()
        status = 0
        polls = 0
        falhas_seguidas = 0

        while True:
            try:
                resp = self._get(
                    path, {"scanId": scan_id}, fase=label
                )
                status = int(resp.json().get("status", 0))
                falhas_seguidas = 0
            except ZAPUnavailableError:
                falhas_seguidas += 1
                if falhas_seguidas >= _MAX_FALHAS_POLL:
                    raise
                logger.warning(
                    "zap_poll_falhou",
                    commit_sha=commit_sha,
                    fase=label,
                    tentativa=falhas_seguidas,
                )
            except (ValueError, TypeError):
                # Resposta ilegível: mantém o último status conhecido e insiste.
                pass

            polls += 1
            if status >= 100:
                logger.info(
                    "zap_fase_concluida",
                    commit_sha=commit_sha,
                    fase=label,
                    duracao_s=int(time.monotonic() - inicio),
                    polls=polls,
                )
                return status

            decorrido = time.monotonic() - inicio
            if decorrido >= teto_s or polls >= teto_polls:
                break
            if self.poll_interval > 0:
                time.sleep(self.poll_interval)

        raise ZAPScanTimeoutError(
            f"ZAP {label} parou em {status}% após {int(time.monotonic() - inicio)}s "
            f"(teto {teto_s}s, {polls} polls) — o daemon respondeu o tempo todo, "
            f"o alvo é que não coube no orçamento"
        )

    # ----- alerts -----

    def _collect_alerts(
        self,
        target_url: str,
        commit_sha: str,
        repo_url: str,
        duracao_s: int = 0,
    ) -> list[Finding]:
        resp = self._get(
            "/JSON/alert/view/alerts/", {"baseurl": target_url}, fase="alerts"
        )
        alerts: list[dict[str, Any]] = resp.json().get("alerts", []) or []
        findings: list[Finding] = []
        for alert in alerts:
            findings.append(self._to_finding(alert, commit_sha, repo_url))
        logger.info(
            "zap_alerts_collected",
            commit_sha=commit_sha,
            target_url=target_url,
            alerts_count=len(findings),
            duracao_s=duracao_s,
        )
        return findings

    def _to_finding(
        self,
        alert: dict[str, Any],
        commit_sha: str,
        repo_url: str,
    ) -> Finding:
        """Converte um alerta do ZAP em `Finding`.

        **A rota vai em `file_path`, e isso é o que faz o dedup funcionar.**
        O `dedup_key` é `source:titulo:file_path:line_number:commit`. Enquanto a
        URL ficava só em `asset`, todo alerta do mesmo tipo colapsava num único
        finding: **369 alertas viraram 8**. Os 8 tipos estavam certos, mas com
        `file_path` vazio — o usuário sabia *que* faltava CSP, não *em quais
        rotas*, que é justamente o que torna um achado de DAST acionável.

        Guardamos o **caminho**, não a URL inteira: o host é sempre o
        `target_url` e só repetiria em todas as linhas. O caminho é o que
        distingue, e é o que a tela mostra na coluna de arquivo.

        `asset` passa a ser o repositório, como nos demais scanners — antes
        recebia a URL, e a UI acabava exibindo um endereço onde mostra o nome do
        projeto.
        """
        risk = alert.get("risk", "Low")
        url = str(alert.get("url", ""))
        return Finding(
            source="zap",
            severity=_RISK_MAP.get(risk, Severity.LOW),
            title=str(alert.get("name", "ZAP Alert"))[:255],
            description=str(alert.get("description", ""))[:2000],
            commit_sha=commit_sha,
            repo_url=repo_url,
            asset=_nome_do_repo(repo_url),
            file_path=_caminho_da_url(url) or None,
            cwe_id=str(alert.get("cweid")) if alert.get("cweid") else None,
            raw_output=alert,
            tier=3,
        )
