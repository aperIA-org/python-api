from pathlib import Path

from pydantic_settings import BaseSettings, SettingsConfigDict

ENV_PATH = Path(__file__).resolve().parents[1] / ".env"


class Settings(BaseSettings):
    model_config = SettingsConfigDict(
        env_file=ENV_PATH,
        env_file_encoding="utf-8",
        case_sensitive=True,
        extra="ignore",
    )

    # ---- Auth (existente — preservado) ----
    SECRET_KEY: str = "change-this-secret-key-with-at-least-32-characters"
    ACCESS_TOKEN_EXPIRE_MINUTES: int = 15
    REFRESH_TOKEN_EXPIRE_DAYS: int = 7

    # ---- GitHub App ----
    GITHUB_APP_ID: str = ""
    GITHUB_PRIVATE_KEY_PATH: str = ""
    GITHUB_WEBHOOK_SECRET: str = ""
    # Slug do App (github.com/apps/<slug>) — usado para montar a URL de
    # instalação em GET /github/connect. Preencher após registrar o App.
    GITHUB_APP_SLUG: str = ""
    # Para onde o /github/callback redireciona o browser do usuário após
    # concluir a conexão (front-end). Vazio → responde JSON em vez de 302.
    GITHUB_CONNECT_REDIRECT_URL: str = ""

    # ---- Anthropic / Claude ----
    ANTHROPIC_API_KEY: str = ""
    CLAUDE_MODEL_REASONING: str = "claude-sonnet-4-6"
    CLAUDE_MODEL_FORMATTING: str = "claude-haiku-4-5-20251001"
    CLAUDE_PROMPT_CACHE_ENABLED: bool = True

    # ---- DAST (ZAP) ----
    ZAP_BASE_URL: str = "http://zap:8090"
    # Default IGUAL ao do docker-compose.scanners.yml (`${ZAP_API_KEY:-changeme}`).
    # Divergir é o bug: com a variável ausente o container subia com "changeme"
    # e o scanner mandava "", então o ZAP recusava toda chamada com
    # "API key incorrect or not supplied" — e o erro chegava ao worker como
    # "Server disconnected", que parece servidor fora do ar, não credencial
    # errada. Uma variável faltando, dois fallbacks discordantes.
    ZAP_API_KEY: str = "changeme"
    # Tetos do scan de DAST, aplicados NO ZAP (não só no cliente). Contra uma
    # aplicação grande o active scan não converge em tempo de pipeline; com o
    # teto no lado do ZAP ele encerra sozinho, a fase chega a 100% e coletamos
    # os alertas parciais em vez de abandonar o scan e voltar de mãos vazias.
    # Ver docs/explicacao-pipeline.md §13 para a escolha dos números.
    ZAP_SPIDER_MAX_DURATION_MIN: int = 3
    # Filhos por nó que o crawler expande. Corta listagem grande (catálogo,
    # paginação), que é a mesma rota repetida e não agrega superfície nova.
    ZAP_SPIDER_MAX_CHILDREN: int = 10
    ZAP_ASCAN_MAX_DURATION_MIN: int = 10
    # Teto por REGRA: impede que uma única regra cara (ex: SQLi time-based)
    # consuma o orçamento inteiro e deixe as outras sem rodar.
    ZAP_ASCAN_MAX_RULE_DURATION_MIN: int = 2
    # Threads de ataque por host. O default do ZAP escala com os núcleos e é o
    # que mais infla o heap (cada thread mantém mensagens em memória). 2 é o
    # que cabe no teto de heap do container.
    ZAP_ASCAN_THREADS_PER_HOST: int = 2
    # Regras de active scan desligadas, por id, separadas por vírgula. Vazio =
    # política completa.
    #
    # 40026 é o **DOM XSS**, e ele é caso à parte: para avaliar DOM ele sobe
    # **Firefox headless de verdade**, dentro do mesmo container e do mesmo
    # cgroup do ZAP. Medido durante um scan do Juice Shop: dois processos pais
    # de Firefox (462 MB + 325 MB) mais os content processes, contra 594 MB do
    # JVM inteiro — o navegador custava mais que o scanner. Com heap correto o
    # container ainda batia no teto de 2 GB e começava a usar swap por causa
    # dele. Nenhum ajuste de `-Xmx` conserta isso: a memória não é do heap, nem
    # do processo Java.
    ZAP_ASCAN_DISABLED_RULES: str = "40026"

    # ---- Threat Intel (OpenCTI) ----
    OPENCTI_URL: str = "http://opencti:8081"
    OPENCTI_TOKEN: str = ""

    # ---- Adversary Emulation (Caldera) ----
    CALDERA_URL: str = "http://caldera:8888"
    # Precisa bater com `api_key_red` de `caldera/local.yml` (montado no
    # container). A imagem gera uma chave aleatória por versão, então alinhar
    # por default só funciona porque fixamos a chave pelo config montado.
    CALDERA_API_KEY: str = "aperia-dev-caldera-red"

    # Libera alvo de DAST em rede interna (localhost, RFC1918, host de rótulo
    # único). Default FALSO: em produção, alvo interno significa usar o aperIA
    # para atacar a própria infraestrutura. Existe porque sem ela não há caminho
    # suportado para testar DAST em desenvolvimento — um Juice Shop local é
    # `http://juice-shop:3000`, exatamente o que a proteção recusa.
    ALLOW_INTERNAL_DAST_TARGETS: bool = False
    CALDERA_SANDBOX_MODE: bool = True
    CALDERA_POLL_INTERVAL: int = 10  # testes injetam 0 via construtor
    CALDERA_AGENT_GROUP: str = "red"

    # ---- AI Security ----
    LLM_GUARD_ENABLED: bool = True

    # ---- Persistência de findings ----
    # Liga a escrita best-effort dos findings no banco a partir dos
    # scan workers. Default True em produção; testes desligam por padrão
    # (ver tests/conftest.py) para não exigir Postgres.
    FINDINGS_PERSISTENCE_ENABLED: bool = True

    # ---- Persistência de status de scan (ScanJob) ----
    # Liga a escrita best-effort do ciclo de vida do ScanJob (criação no
    # start_pipeline + updates de status por tier nos workers). Mesmo
    # racional do flag de findings: default True; testes desligam por padrão.
    SCAN_PERSISTENCE_ENABLED: bool = True

    # Minutos sem progresso a partir dos quais um ScanJob ainda "queued"/
    # "running" é considerado travado (stale) e pode ser marcado como failed.
    # Existe porque o Redis é o broker: se a fila se perde (restart da stack,
    # worker morto), a linha no Postgres sobrevive sem ninguém para concluí-la
    # e o commit fica permanentemente barrado pelo 409 do disparo manual.
    # Usado na varredura de boot da API e na checagem preguiçosa do disparo.
    SCAN_STALE_AFTER_MINUTES: int = 30

    # ---- Checkout do repositório ----
    # Teto para cada operação de rede do checkout efêmero (fetch raso do
    # commit). Existe porque um repositório enorme ou uma conexão pendurada
    # não pode prender o worker para sempre — sem timeout a task ficaria viva
    # e o ScanJob preso em "running" até a varredura de jobs travados.
    REPO_CHECKOUT_TIMEOUT: int = 300

    # ---- Celery / Redis ----
    # Default aponta para o hostname do container (docker-compose service "redis"),
    # não localhost — produção depende de DNS interno. Override via env em dev.
    REDIS_URL: str = "redis://redis:6379/0"
    CELERY_BROKER_URL: str = ""
    CELERY_RESULT_BACKEND: str = ""
    CELERY_TASK_ALWAYS_EAGER: bool = False
    CELERY_TASK_EAGER_PROPAGATES: bool = False


settings = Settings()
