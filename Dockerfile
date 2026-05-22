# aperIA — imagem base com todos os scanners pinados.
#
# Versões fixas — nunca ``latest`` em ferramentas de segurança.
# Mudanças de versão afetam regra-base + comportamento dos scanners
# e exigem regression tests.
FROM python:3.11-slim AS aperia-base

ARG TRUFFLEHOG_VERSION=3.63.7
ARG SEMGREP_VERSION=1.62.0
ARG TRIVY_VERSION=0.49.1
ARG PROWLER_VERSION=4.2.0

ENV PYTHONUNBUFFERED=1 \
    PIP_NO_CACHE_DIR=1 \
    DEBIAN_FRONTEND=noninteractive

WORKDIR /app

# Dependências do sistema + repositório oficial do Trivy (.deb)
RUN apt-get update \
    && apt-get install -y --no-install-recommends \
       curl \
       ca-certificates \
       gnupg \
       lsb-release \
       git \
    && curl -sSfL https://aquasecurity.github.io/trivy-repo/deb/public.key \
       | gpg --dearmor -o /usr/share/keyrings/trivy.gpg \
    && echo "deb [signed-by=/usr/share/keyrings/trivy.gpg] https://aquasecurity.github.io/trivy-repo/deb $(lsb_release -sc) main" \
       > /etc/apt/sources.list.d/trivy.list \
    && apt-get update \
    && apt-get install -y --no-install-recommends "trivy=${TRIVY_VERSION}" \
    && apt-get clean \
    && rm -rf /var/lib/apt/lists/*

# TruffleHog (Go binary) — instalador oficial pinado
RUN curl -sSfL https://raw.githubusercontent.com/trufflesecurity/trufflehog/main/scripts/install.sh \
    | sh -s -- -b /usr/local/bin "v${TRUFFLEHOG_VERSION}"

# Semgrep + Prowler via pip (mais simples que binários standalone)
RUN pip install --no-cache-dir \
       "semgrep==${SEMGREP_VERSION}" \
       "prowler==${PROWLER_VERSION}"

# Dependências Python da aperIA
COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY main.py ./
COPY app ./app
COPY alembic ./alembic
COPY alembic.ini ./

EXPOSE 8000

CMD ["uvicorn", "main:app", "--host", "0.0.0.0", "--port", "8000"]
