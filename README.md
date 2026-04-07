# Python API

API HTTP em FastAPI para cadastro e consulta de usuarios, com arquitetura em camadas inspirada em DDD.

Este documento foi escrito para:

- Desenvolvedores juniores entenderem o fluxo ponta a ponta.
- Desenvolvedores seniores validarem regras de negocio e decisoes tecnicas.
- Time de DevOps operar a aplicacao com seguranca em ambiente de nuvem.
- Servir de base para IA interna sem quebrar a estrutura atual do projeto.

## 1. Objetivo e Escopo

O servico oferece 3 rotas principais:

- `GET /health`: valida se a API esta no ar.
- `POST /users`: cria usuario com validacoes de negocio e hash de senha.
- `GET /users/{user_id}`: consulta um usuario por UUID.

Fora de escopo atual:

- Autenticacao/login.
- Atualizacao e remocao de usuarios.
- Migracoes versionadas de schema (exemplo: Alembic).

## 2. Arquitetura do Projeto

Estrutura principal:

- `app/domain`: entidades e contratos (regras do dominio sem dependencia de framework).
- `app/application`: casos de uso (orquestracao de regras de negocio).
- `app/infrastructure`: banco, modelos SQLAlchemy e repositorios concretos.
- `app/presentation`: rotas FastAPI e schemas de entrada/saida.

Fluxo de uma requisicao de criacao:

1. Rota recebe payload e injeta sessao de banco.
2. Caso de uso aplica validacoes.
3. Repositorio persiste no banco e devolve entidade.
4. Rota converte para schema de resposta.

## 3. Regras de Negocio (Usuarios)

Implementadas em `CreateUserUseCase`.

### 3.1 Username

- Faz normalizacao Unicode NFKC e trim em `username`.
- So aceita letras, numeros e espaco (`^[A-Za-z0-9 ]+$`).
- Nao pode ficar vazio apos trim.

### 3.2 E-mail

- Faz normalizacao Unicode NFKC e trim em `email`.
- Armazena em minusculo.
- Regex de formato basico: `^[^\s@]+@[^\s@]+\.[^\s@]+$`.
- Regra de unicidade:
  - Pre-check no caso de uso via `exists_by_email`.
  - Constraint unica no banco (`unique=True` no modelo).

### 3.3 Senha

- Nao passa por trim/normalizacao (preserva exatamente o que usuario digitou).
- Nao pode ser vazia (`""`).
- Minimo de 8 e maximo de 128 caracteres.
- Deve conter pelo menos:
  - 1 letra maiuscula.
  - 1 letra minuscula.
  - 1 numero.
  - 1 caractere especial.
- Antes de persistir, senha e hasheada com Argon2.

### 3.4 Datas

- `created_at` e `updated_at` sao preenchidos pela aplicacao com horario de Brasilia.
- Sao persistidas como datetime sem timezone (naive), usando horario local de Brasilia como referencia.

## 4. Contratos da API

Base URL local: `http://127.0.0.1:8000`

### 4.1 Health

- Metodo e rota: `GET /health`
- Resposta 200:

```json
{
  "status": "ok"
}
```

### 4.2 Criar Usuario

- Metodo e rota: `POST /users`
- Body JSON:

```json
{
  "username": "Maria Silva",
  "password": "Senha@123",
  "email": "maria@empresa.com"
}
```

- Respostas:
  - `201`: usuario criado.
  - `400`: erro de validacao de negocio.
  - `409`: e-mail duplicado (detecao atual por parsing textual de `IntegrityError`).
  - `500`: erro de permissao de escrita no banco (quando detectado).

- Exemplo resposta `201`:

```json
{
  "id": "14d57567-a2ea-4f14-95f6-06476a2f39b8"
}
```

### 4.3 Buscar Usuario por ID

- Metodo e rota: `GET /users/{user_id}`
- Parametro: UUID valido.
- Respostas:
  - `200`: usuario encontrado.
  - `404`: usuario nao encontrado.

- Exemplo resposta `200`:

```json
{
  "id": "14d57567-a2ea-4f14-95f6-06476a2f39b8",
  "username": "Maria Silva",
  "email": "maria@empresa.com",
  "created_at": "2026-04-07T10:12:30",
  "updated_at": "2026-04-07T10:12:30"
}
```

## 5. Banco de Dados

Banco esperado: PostgreSQL via psycopg.

Tabela principal `users`:

- `id` UUID (PK, default `gen_random_uuid()`).
- `username` varchar(255), not null.
- `password` text, not null (hash Argon2).
- `email` varchar(500), not null, unique.
- `created_at` datetime.
- `updated_at` datetime.

## 6. Configuracao de Ambiente

Importante sobre este repositorio:

- O `docker-compose.yml` atual sobe apenas o servico da API.
- Nao existe servico `db` (PostgreSQL) no Compose deste projeto.
- Portanto, para rodar `POST /users` e `GET /users/{user_id}`, voce precisa de um PostgreSQL externo (exemplo: cloud) corretamente configurado nas variaveis.

Variaveis aceitas:

- `DATABASE_URL` (prioridade maxima).
- `DB_HOST`
- `DB_PORT`
- `DB_NAME`
- `DB_USER`
- `DB_PASSWORD`
- `DB_FORCE_IPV4` (`true/false`)

Ordem de resolucao:

1. Variavel de ambiente do processo.
2. Arquivo `.env` local.
3. Valor padrao do codigo.

Exemplo de `.env` para banco em cloud (recomendado neste projeto):

```env
DB_HOST=seu-host-postgres-cloud
DB_PORT=5432
DB_NAME=postgres
DB_USER=python_api
DB_PASSWORD=sua-senha-segura
DB_FORCE_IPV4=false
```

Observacao sobre `DB_HOST=db`:

- Use `DB_HOST=db` somente se voce adicionar manualmente um servico PostgreSQL no Compose com nome `db`.
- Se mantiver o Compose atual (somente API), `DB_HOST=db` nao funciona.

Exemplo usando URL unica:

```env
DATABASE_URL=postgresql+psycopg://python_api:sua-senha-segura@seu-host-postgres-cloud:5432/postgres
```

## 7. Execucao Local com Docker

### 7.1 Requisitos

- Docker
- Docker Compose v2+

### 7.2 Subir aplicacao

Antes de subir, configure o `.env` apontando para um PostgreSQL acessivel (normalmente cloud neste projeto).

```bash
docker compose up --build
```

### 7.3 Testar

```bash
curl http://127.0.0.1:8000/health
```

Nota:

- `GET /health` valida apenas disponibilidade da API.
- Esse endpoint nao garante que o banco esta acessivel.
- Para validar banco, teste tambem uma rota que acessa dados, como `POST /users`.

### 7.4 Parar

```bash
docker compose down
```

## 8. Observabilidade e Logs

- Logs aparecem no stdout/stderr do processo Uvicorn.
- Em Docker Compose:

```bash
docker compose logs -f api
```

- No startup a API faz check leve de conectividade (`SELECT 1`).
- Se banco estiver indisponivel no startup, a API permanece ativa e loga warning com stack trace.

## 9. Seguranca e Boas Praticas Operacionais

Ja aplicado no projeto:

- `.dockerignore` exclui `.env` e arquivos sensiveis comuns.
- `Dockerfile` copia apenas arquivos necessarios para runtime (`main.py` e `app/`).
- Segredos entram em runtime via `env_file` no Compose, nao no build da imagem.

Recomendacoes adicionais para nuvem:

1. Nao usar `env_file` em producao; usar secret manager da plataforma.
2. Usuario da aplicacao no banco com privilegios minimos.
3. TLS entre API e banco.
4. Politica de rotacao de senha/credenciais.

## 10. Limites Tecnicos Atuais e Riscos

1. Migracao de schema ainda nao e versionada.
   - Hoje nao existe Alembic no projeto.
   - Recomendacao: adotar migracoes antes de ambiente produtivo critico.

2. Tratamento de e-mail duplicado na rota ainda e fragil.
   - Implementacao atual usa parsing de texto do erro SQL (`IntegrityError`).
   - Recomendacao: usar metadados estruturados do PostgreSQL (`sqlstate`, `constraint_name`).

3. Startup nao falha quando banco esta indisponivel.
   - Bom para resiliencia de boot, mas pode adiar erro para primeira escrita/leitura.
   - Em nuvem, combinar com readiness probe conectado ao banco quando necessario.

## 11. Guia Rapido para Novos Desenvolvedores

1. Garanta um PostgreSQL acessivel (cloud ou local externo ao Compose atual).
2. Configure o `.env` com `DATABASE_URL` ou `DB_HOST/DB_PORT/DB_NAME/DB_USER/DB_PASSWORD` validos.
3. Suba a API com Docker Compose.
4. Chame `GET /health` para validar que a API iniciou.
5. Teste `POST /users` para validar conectividade com banco.
6. Consulte o usuario por UUID em `GET /users/{user_id}`.
7. Em caso de erro, inspecione logs e valide variaveis de ambiente/rede.

## 12. Avaliacao em 3 Perfis e Ajustes Aplicados

Esta secao registra a revisao solicitada e como ela impactou o texto final.

### 12.1 Avaliacao 1: Estagiario Desenvolvedor

Feedback:

- Faltava explicar a diferenca entre validacao de schema (Pydantic) e regra de negocio (use case).
- Exemplos de request/response eram poucos.
- Nao estava claro o passo a passo minimo para comecar.

Ajustes aplicados:

- Adicionado guia rapido de onboarding.
- Adicionados exemplos completos de payload e respostas por rota.
- Reforcada explicacao de regras de negocio por campo.

### 12.2 Avaliacao 2: Desenvolvedor Senior

Feedback:

- Necessario explicitar comportamentos reais do codigo (inclusive limitacoes atuais).
- Necessario documentar risco de concorrencia no cadastro por e-mail.
- Necessario separar estado atual de recomendacoes futuras.

Ajustes aplicados:

- Secao de riscos tecnicos e estado atual adicionada.
- Documentado pre-check + constraint unica de e-mail.
- Documentadas recomendacoes sem mascarar o que ja esta implementado.

### 12.3 Avaliacao 3: Responsavel DevOps

Feedback:

- Faltavam detalhes de operacao em nuvem e seguranca de segredos.
- Faltava orientar observabilidade e readiness.
- Faltava deixar claro como configurar ambiente sem embutir segredo no build.

Ajustes aplicados:

- Adicionadas secoes de seguranca operacional e logs.
- Descrita estrategia atual de build/runtime para segredos.
- Incluidas recomendacoes objetivas para cloud (secret manager, privilegio minimo, TLS).

## 13. Proximos Passos Recomendados

1. Introduzir Alembic para migracoes versionadas.
2. Tornar tratamento de duplicidade de e-mail deterministico por metadados do erro SQL.
3. Adicionar testes automatizados para regras de senha, e-mail e cenarios de concorrencia.
4. Definir health/readiness separados para operacao em orchestrator.