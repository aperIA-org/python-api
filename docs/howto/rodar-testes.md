# Como rodar os testes

Rode a suíte de testes do aperIA — que mocka Claude e scanners — para validar
a lógica sem precisar de chaves, créditos ou repositório real.

## 1. Rodar localmente (`.venv`)

```bash
source .venv/bin/activate
pytest tests/ -q                          # 473 testes
pytest tests/e2e/test_full_pipeline.py -v # canvas completo mockado
```

## 2. Rodar com cobertura

O gate de cobertura mínima é 70%:

```bash
pytest tests/ --cov=app --cov-fail-under=70
```

## 3. Rodar dentro do container

Se preferir não instalar dependências localmente:

```bash
docker compose -f docker-compose.base.yml exec api pytest tests/ -q
```

## 4. Localizar o teste certo

A suíte está organizada por camada:

| Diretório | Cobre |
|---|---|
| `tests/unit/` | domínio, prompts, circuit breaker |
| `tests/integration/` | scanners mockados via `respx`, SQLite em memória, Celery eager |
| `tests/e2e/test_full_pipeline.py` | canvas inteiro (pipeline ponta a ponta mockado) |

Testes de persistência específicos: `test_finding_repository.py` e
`test_dedup_e2e.py` (repositório síncrono + dedup via UNIQUE, em SQLite) e
`test_finding_persistence_worker.py` (worker grava no banco, `ON CONFLICT` não
duplica, flag off = nada gravado, falha de banco não quebra o scan).

## 5. Fixtures globais

`tests/conftest.py` tem fixtures **autouse** que:

- Ligam o modo eager do Celery (`CELERY_TASK_ALWAYS_EAGER`).
- Resetam o circuit breaker do Claude entre testes.
- Desligam `FINDINGS_PERSISTENCE_ENABLED` por padrão (para os testes de worker
  não exigirem Postgres) — os testes de persistência religam a flag e injetam
  SQLite em memória.

Se um teste novo depender de estado global (circuit breaker, flags de
config), confira primeiro se `conftest.py` já cobre o reset antes de duplicar
setup/teardown manual.

## Próximos passos

- Consultar as variáveis de ambiente relevantes para os testes (ex.:
  `FINDINGS_PERSISTENCE_ENABLED`, `CELERY_TASK_ALWAYS_EAGER`) →
  [referencia.md](../referencia.md).
