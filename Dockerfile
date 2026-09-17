# aperIA — imagem base com todos os scanners pinados.
#
# Versões fixas — nunca ``latest`` em ferramentas de segurança.
# Mudanças de versão afetam regra-base + comportamento dos scanners
# e exigem regression tests.
FROM python:3.11-slim-bookworm AS aperia-base

ARG TRUFFLEHOG_VERSION=3.63.7
# 1.62.0 (fev/2024) parou de conseguir ler o registro de regras: o registro
# passou a servir regras com severidade `MEDIUM`, e aquela versao so aceita
# ERROR/WARNING/INFO/INVENTORY/EXPERIMENT. Uma regra invalida aborta a config
# INTEIRA, entao `--config=auto` e `p/default` devolviam ZERO findings com
# `InvalidRuleSchemaError` — e como o parser so lia `results`, o Tier 2
# registrava `done` com 0. Silencio indistinguivel de "repositorio limpo".
# Medido no mesmo repo-alvo: 1.62.0 + p/default = 0 findings; 1.174.0 = 40.
ARG SEMGREP_VERSION=1.174.0
# 0.49.1 não está mais disponível (apt repo só serve a latest; GitHub
# removeu binários de releases antigas). Atualizado para a versão atual.
ARG TRIVY_VERSION=0.71.0
ARG PROWLER_VERSION=4.2.0

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    DEBIAN_FRONTEND=noninteractive

WORKDIR /app

# Dependências do sistema
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       curl \
       ca-certificates \
       git \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# Trivy — release oficial pinado do GitHub.
# O repositório apt do Trivy só serve a última versão, então não dá para
# pinar via apt. Baixamos o tarball da release exata para manter reprodutível.
RUN curl -sSfL "https://github.com/aquasecurity/trivy/releases/download/v${TRIVY_VERSION}/trivy_${TRIVY_VERSION}_Linux-64bit.tar.gz" \
       -o /tmp/trivy.tar.gz \
    && tar -xzf /tmp/trivy.tar.gz -C /usr/local/bin trivy \
    && rm /tmp/trivy.tar.gz \
    && trivy --version

# TruffleHog (Go binary) — instalador oficial pinado
RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
    | sh -s -- -b /usr/local/bin "v${TRUFFLEHOG_VERSION}"

# Semgrep e Prowler, cada um no seu proprio venv.
#
# Eles NAO cabem no mesmo site-packages: o Prowler 4.2.0 pina
# `jsonschema==4.22.0` (igualdade exata) e o Semgrep 1.174.0 exige
# `jsonschema~=4.25.1`. Sem intersecao, `pip install` dos dois juntos termina em
# `ResolutionImpossible` — foi o que quebrou o build ao atualizar o Semgrep.
#
# Compartilhar ambiente nunca teve beneficio aqui: os dois sao CLIs chamados por
# `subprocess`, e nada no codigo os importa. O acoplamento era so do `pip
# install` unico. Com um venv por ferramenta, atualizar uma nao pode mais
# quebrar a outra, que e o que se quer de ferramenta de seguranca pinada.
#
# Os symlinks mantem `semgrep` e `prowler` no PATH, entao os scanners continuam
# invocando pelo nome, sem saber que existe venv.
RUN python -m venv /opt/semgrep \
    && /opt/semgrep/bin/pip install --no-cache-dir "semgrep==${SEMGREP_VERSION}" \
    && ln -s /opt/semgrep/bin/semgrep /usr/local/bin/semgrep \
    && semgrep --version

RUN python -m venv /opt/prowler \
    && /opt/prowler/bin/pip install --no-cache-dir "prowler==${PROWLER_VERSION}" \
    && ln -s /opt/prowler/bin/prowler /usr/local/bin/prowler \
    && prowler --version

# Dependências Python da aperIA
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py ./
COPY app ./app
COPY alembic ./alembic
COPY alembic.ini ./

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
