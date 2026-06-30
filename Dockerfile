# aperIA — imagem base com todos os scanners pinados.
#
# Versões fixas — nunca ``latest`` em ferramentas de segurança.
# Mudanças de versão afetam regra-base + comportamento dos scanners
# e exigem regression tests.
FROM python:3.11-slim-bookworm AS aperia-base

ARG TRUFFLEHOG_VERSION=3.63.7
ARG SEMGREP_VERSION=1.62.0
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
