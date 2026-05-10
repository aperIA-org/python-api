# Deploy — aperIA

## Opção A: Oracle Cloud Free Tier + Coolify (€0/mês)

### 1. Criar VM no Oracle Cloud
- Entrar em cloud.oracle.com → Compute → Instances → Create
- Shape: **VM.Standard.A1.Flex** (ARM) — Always Free
  - 4 OCPUs, 24GB RAM (cota gratuita total dividida entre VMs)
- OS: Ubuntu 22.04
- Abrir portas: 22 (SSH), 80 (HTTP), 443 (HTTPS), 8000 (API)

### 2. Instalar Coolify na VM
```bash
curl -fsSL https://cdn.coollabs.io/coolify/install.sh | bash
```
Acesse `http://<ip-vm>:8000` e configure o painel.

### 3. PostgreSQL — Neon.tech (gratuito)
- Criar conta em neon.tech
- New Project → copiar a connection string:
  ```
  postgresql+asyncpg://usuario:senha@ep-xxx.us-east-2.aws.neon.tech/aperia?sslmode=require
  ```
- Usar como `DATABASE_URL` no `.env`

### 4. Redis — Upstash (gratuito até 10k req/dia)
- Criar conta em upstash.com → Redis → Create Database
- Copiar URL no formato `rediss://default:senha@xxx.upstash.io:6379`
- Usar como `REDIS_URL` no `.env`

### 5. Deploy via Coolify
- Coolify → New Resource → Docker Compose
- Apontar para o repositório GitHub
- Selecionar `docker-compose.prod.yml`
- Configurar variáveis de ambiente (copiar do `.env.example`)
- Deploy

---

## Opção B: Hetzner CX32 (~€7/mês) — Mais robusto

```bash
# Criar servidor Hetzner CX32 (4 vCPU, 8GB RAM, Ubuntu 22.04)
# SSH no servidor

# Instalar Docker
curl -fsSL https://get.docker.com | sh

# Instalar Coolify
curl -fsSL https://cdn.coollabs.io/coolify/install.sh | bash

# Clonar repo e configurar
git clone https://github.com/OCR-aperIA/python-api.git
cd python-api
cp .env.example .env
# Editar .env com suas credenciais

# Subir em produção
docker compose -f docker-compose.prod.yml up -d
```

---

## Variáveis de Ambiente Obrigatórias para Deploy

```env
# Database (Neon.tech)
DATABASE_URL=postgresql+asyncpg://user:pass@host.neon.tech/aperia?sslmode=require

# Redis (Upstash ou container local)
REDIS_URL=rediss://default:pass@host.upstash.io:6379
REDIS_PASSWORD=sua_senha_redis

# GitHub App
GITHUB_APP_ID=...
GITHUB_PRIVATE_KEY_PATH=/secrets/github.pem
GITHUB_WEBHOOK_SECRET=...
GITHUB_TOKEN=...

# Claude API
ANTHROPIC_API_KEY=sk-ant-...

# Caldera (sandbox obrigatório)
CALDERA_API_KEY=...
CALDERA_SANDBOX_MODE=true

# App
ENV=production
LOG_LEVEL=INFO
```

---

## Alembic — Migrations em Produção

```bash
# Rodar migrations antes de subir a API
docker compose -f docker-compose.prod.yml run --rm api alembic upgrade head
```

---

## Escanners Opcionais (ZAP, OpenVAS, Wazuh)

Deixe as variáveis vazias para pular no pipeline:
```env
ZAP_TARGET_URL=        # vazio = ZAP pulado
OPENVAS_TARGET_IP=     # vazio = OpenVAS pulado
WAZUH_AGENT_ID=        # vazio = Wazuh pulado
```
Para habilitar, adicione esses serviços ao `docker-compose.prod.yml` e configure as variáveis.
