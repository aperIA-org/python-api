# secrets/ — chave privada do GitHub App

Este diretório é montado **read-only** em `/app/secrets` nos containers que
precisam emitir *installation token*: `api`, `worker_tier1`, `worker_tier2`,
`worker_analysis` e `worker_reporting` (ver `docker-compose.base.yml`).
`worker_tier3` não monta — ele não fala com o GitHub.

## Convenção

1. Baixe a chave em https://github.com/settings/apps → seu App → "Generate a
   private key". O GitHub salva o arquivo como
   `<slug>.<AAAA-MM-DD>.private-key.pem`.
2. Copie o arquivo **com o nome original** para cá:

   ```bash
   cp ~/Downloads/aperia-aspm.2026-07-28.private-key.pem secrets/
   chmod 600 secrets/aperia-aspm.2026-07-28.private-key.pem
   ```

3. Aponte o `.env` para o caminho **de dentro do container**, `/app/secrets/`
   seguido do mesmo nome de arquivo:

   ```dotenv
   GITHUB_PRIVATE_KEY_PATH=/app/secrets/aperia-aspm.2026-07-28.private-key.pem
   ```

O nome do arquivo é livre — o que **não** pode divergir é o par
`GITHUB_PRIVATE_KEY_PATH` ↔ nome real dentro de `secrets/`. Se divergir,
`get_installation_token()` estoura `FileNotFoundError` e o pipeline para antes
do checkout: sem token os workers de T1/T2 não clonam o repositório e não há o
que escanear.

## Por que volume e não `COPY`

A chave já morou em `app/secrets/`, que o `COPY app ./app` do `Dockerfile`
assava na imagem. Credencial dentro da imagem viaja em toda camada, todo cache
de registry e todo `docker push`. Hoje `app/secrets/`, `secrets/` e `**/*.pem`
estão no `.dockerignore`; a chave entra apenas pelo bind mount.

Para conferir que a imagem continua limpa:

```bash
docker run --rm --entrypoint sh python-api-api -c 'ls /app/app/secrets'
# esperado: "No such file or directory"
```

## Git

O `.gitignore` ignora `secrets/*` e reabre só este `README.md`. Nenhum `.pem`
daqui chega ao repositório — confira com
`git check-ignore -v secrets/<arquivo>.pem`.

## Rodando fora do Docker

Sem container não existe `/app`. Para subir o uvicorn direto no host, sobrescreva
com o caminho do host:

```bash
GITHUB_PRIVATE_KEY_PATH=$PWD/secrets/aperia-aspm.2026-07-28.private-key.pem \
  .venv/bin/uvicorn main:app
```
