"""
Extração heurística de sinais de contexto de negócio de um repositório clonado.
Não executa código — apenas leitura de arquivos com limites estritos.
"""
import json
import re
from pathlib import Path

# Extensões de código fonte consideradas para análise de padrões
_SOURCE_EXTS = {".py", ".js", ".ts", ".rb", ".go", ".java", ".cs", ".php", ".kt", ".rs"}

# Diretórios ignorados durante o scan de código
_SKIP_DIRS = {
    "node_modules", "__pycache__", "vendor", ".git", ".tox",
    "venv", ".venv", "env", "dist", "build", ".next", "coverage",
}

# Dependências → domínio financeiro (PCI-DSS)
_FINANCIAL_DEPS = {
    "stripe", "braintree", "adyen", "paypal", "pagarme", "pagar.me",
    "iugu", "mercadopago", "pagseguro", "rede", "cielo", "gerencianet",
    "square", "razorpay", "mollie", "checkout.com",
}

# Dependências → dados de saúde (HIPAA)
_HEALTH_DEPS = {
    "fhir", "hl7", "pydicom", "pymedphys", "hl7apy", "fhirclient",
    "smart-on-fhir", "health-data",
}

# Dependências → comunicação com usuários (PII/LGPD)
_PII_DEPS = {
    "sendgrid", "twilio", "mailchimp", "nodemailer", "mailgun",
    "ses", "sns", "boto3",  # boto3 acessa dados AWS (S3 = possível PII)
    "django", "fastapi", "flask",  # web frameworks implica usuários
}

# Frameworks detectáveis
_FRAMEWORK_MAP = {
    "fastapi": "web_api", "flask": "web_api", "django": "web_fullstack",
    "aiohttp": "web_api", "sanic": "web_api", "tornado": "web_api",
    "express": "web_api", "nestjs": "web_api", "koa": "web_api",
    "nextjs": "frontend", "react": "frontend", "vue": "frontend",
    "angular": "frontend", "svelte": "frontend",
    "spring": "web_api", "quarkus": "web_api", "micronaut": "web_api",
    "rails": "web_fullstack", "sinatra": "web_api",
    "celery": "data_pipeline", "airflow": "data_pipeline",
    "kafka": "data_pipeline", "rabbitmq": "data_pipeline",
}

# Padrões de entidades/modelos relevantes para negócio
_MODEL_PATTERNS = [
    r"class\s+(User|Customer|Patient|Order|Payment|Invoice|Account|"
    r"Transaction|Product|Subscription|Tenant|Billing|Record|"
    r"Employee|Contract|Claim|Policy|Beneficiary)\b",
]

# Padrões de rotas sensíveis
_ROUTE_PATTERNS = [
    r"[\"\'](/auth|/login|/signup|/register)[\"\'\/]",
    r"[\"\'](/payment|/checkout|/billing|/subscription)[\"\'\/]",
    r"[\"\'](/admin|/dashboard|/management)[\"\'\/]",
    r"[\"\'](/patient|/record|/health|/medical)[\"\'\/]",
    r"[\"\'](/user|/profile|/account|/personal)[\"\'\/]",
    r"[\"\'](/api/v\d|/v\d/)[\"\'\/]",
]

# Campos que indicam dados sensíveis
_SENSITIVE_FIELDS = [
    "cpf", "cnpj", "ssn", "sin", "nif", "rg",
    "credit_card", "card_number", "cvv", "card_cvv",
    "password_hash", "hashed_password", "password_salt",
    "bank_account", "routing_number", "iban", "swift",
    "medical_record", "patient_id", "diagnosis", "prescription",
    "date_of_birth", "dob", "birth_date",
    "social_security", "passport_number", "driver_license",
]


def extract_repo_signals(repo_path: str) -> dict:
    """
    Extrai sinais de contexto de negócio de um repositório clonado.
    Retorna dict com todas as categorias de sinais detectadas.
    Nunca levanta exceção — sempre retorna um dict (possivelmente parcial).
    """
    path = Path(repo_path)
    return {
        "dir_structure":    _get_dir_structure(path),
        "dependencies":     _get_dependencies(path),
        "env_vars":         _get_env_vars(path),
        "readme_excerpt":   _get_readme(path),
        "code_patterns":    _get_code_patterns(path),
        "has_migrations":   _has_migrations(path),
        "frameworks":       _detect_frameworks(_get_dependencies(path)),
        "cloud_providers":  _detect_cloud_providers(path),
        "ci_cd":            _detect_ci_cd(path),
    }


# ── Extratores individuais ─────────────────────────────────────────────────


def _get_dir_structure(path: Path) -> list[str]:
    try:
        return sorted(
            d.name for d in path.iterdir()
            if d.is_dir() and not d.name.startswith(".")
        )[:60]
    except Exception:
        return []


def _get_dependencies(path: Path) -> dict[str, list[str]]:
    result: dict[str, list[str]] = {}

    # Python
    for fname in ("requirements.txt", "requirements-prod.txt", "pyproject.toml"):
        fp = path / fname
        if fp.exists():
            result["python"] = _parse_requirements(fp)
            break

    # Node
    pkg = path / "package.json"
    if pkg.exists():
        try:
            data = json.loads(pkg.read_text(errors="replace"))
            deps = list(data.get("dependencies", {}).keys())
            deps += list(data.get("devDependencies", {}).keys())
            result["node"] = [d.lstrip("@").split("/")[-1] for d in deps[:120]]
        except Exception:
            pass

    # Go
    gomod = path / "go.mod"
    if gomod.exists():
        result["go"] = _parse_gomod(gomod)

    # Ruby
    gemfile = path / "Gemfile"
    if gemfile.exists():
        result["ruby"] = _parse_gemfile(gemfile)

    # Java/Kotlin
    for fname in ("pom.xml", "build.gradle", "build.gradle.kts"):
        fp = path / fname
        if fp.exists():
            result["jvm"] = _parse_jvm_deps(fp)
            break

    return result


def _parse_requirements(fp: Path) -> list[str]:
    names = []
    try:
        for line in fp.read_text(errors="replace").splitlines():
            line = line.strip()
            if not line or line.startswith(("#", "-", "git+")):
                continue
            # strip version specifier: stripe==5.0 → stripe
            name = re.split(r"[>=<!;\[]", line)[0].strip().lower()
            if name:
                names.append(name)
    except Exception:
        pass
    return names[:150]


def _parse_gomod(fp: Path) -> list[str]:
    names = []
    try:
        in_require = False
        for line in fp.read_text(errors="replace").splitlines():
            line = line.strip()
            if line.startswith("require ("):
                in_require = True
                continue
            if in_require and line == ")":
                in_require = False
                continue
            if in_require or line.startswith("require "):
                parts = line.split()
                if parts:
                    pkg = parts[0].split("/")[-1].lower()
                    names.append(pkg)
    except Exception:
        pass
    return names[:100]


def _parse_gemfile(fp: Path) -> list[str]:
    names = []
    try:
        for line in fp.read_text(errors="replace").splitlines():
            m = re.match(r"""gem\s+['"]([^'"]+)['"]""", line.strip())
            if m:
                names.append(m.group(1).lower())
    except Exception:
        pass
    return names[:100]


def _parse_jvm_deps(fp: Path) -> list[str]:
    names = []
    try:
        content = fp.read_text(errors="replace")
        # pom.xml: <artifactId>stripe-java</artifactId>
        names += re.findall(r"<artifactId>([^<]+)</artifactId>", content)
        # gradle: implementation 'com.stripe:stripe-java:...'
        names += re.findall(r"""['"][\w.]+:([\w-]+):[^'"]+['"]""", content)
    except Exception:
        pass
    return [n.lower() for n in names[:100]]


def _get_env_vars(path: Path) -> list[str]:
    for fname in (".env.example", ".env.sample", ".env.template", ".env.dist"):
        fp = path / fname
        if fp.exists():
            try:
                keys = []
                for line in fp.read_text(errors="replace").splitlines():
                    line = line.strip()
                    if line and not line.startswith("#") and "=" in line:
                        keys.append(line.split("=")[0].strip().lower())
                return keys[:120]
            except Exception:
                pass
    return []


def _get_readme(path: Path) -> str:
    for fname in ("README.md", "README.rst", "README.txt", "README", "readme.md"):
        fp = path / fname
        if fp.exists():
            try:
                return fp.read_text(errors="replace")[:2500]
            except Exception:
                pass
    return ""


def _get_code_patterns(path: Path) -> dict:
    """
    Faz scan em até 25 arquivos fonte (máx 5000 chars cada) buscando:
    - Nomes de entidades/modelos
    - Padrões de rota sensíveis
    - Campos de dados sensíveis
    """
    model_names: set[str] = set()
    route_patterns: set[str] = set()
    sensitive_fields: set[str] = set()

    compiled_models = [re.compile(p, re.IGNORECASE) for p in _MODEL_PATTERNS]
    compiled_routes = [re.compile(p, re.IGNORECASE) for p in _ROUTE_PATTERNS]

    files_checked = 0
    for file_path in path.rglob("*"):
        if files_checked >= 25:
            break
        if file_path.suffix not in _SOURCE_EXTS:
            continue
        if any(part in _SKIP_DIRS for part in file_path.parts):
            continue

        try:
            content = file_path.read_text(errors="replace")[:5000]
            content_lower = content.lower()

            for pat in compiled_models:
                for m in pat.finditer(content):
                    model_names.add(m.group(1))

            for pat in compiled_routes:
                for m in pat.finditer(content):
                    route_patterns.add(m.group(1))

            for field_name in _SENSITIVE_FIELDS:
                if field_name in content_lower:
                    sensitive_fields.add(field_name)

            files_checked += 1
        except Exception:
            continue

    return {
        "model_names": sorted(model_names),
        "route_patterns": sorted(route_patterns),
        "sensitive_fields": sorted(sensitive_fields),
    }


def _has_migrations(path: Path) -> bool:
    for candidate in ("migrations", "alembic", "db/migrate", "database/migrations", "flyway"):
        if (path / candidate).is_dir():
            return True
    return False


def _detect_frameworks(dependencies: dict[str, list[str]]) -> list[str]:
    all_deps = {d.lower() for deps in dependencies.values() for d in deps}
    return [_FRAMEWORK_MAP[dep] for dep in all_deps if dep in _FRAMEWORK_MAP]


def _detect_cloud_providers(path: Path) -> list[str]:
    providers = []
    indicators = {
        "aws":   ["boto3", "aws-sdk", "serverless", "cdk", ".aws"],
        "gcp":   ["google-cloud", "firebase", "gcloud", "appengine"],
        "azure": ["azure-", "azurewebsites", "arm-template"],
    }
    content_search = ""
    for fname in (".env.example", "docker-compose.yml", "serverless.yml"):
        fp = path / fname
        if fp.exists():
            try:
                content_search += fp.read_text(errors="replace").lower()
            except Exception:
                pass

    for provider, signals in indicators.items():
        if any(sig in content_search for sig in signals):
            providers.append(provider)
    return providers


def _detect_ci_cd(path: Path) -> list[str]:
    ci_files = {
        ".github/workflows": "github_actions",
        ".gitlab-ci.yml":    "gitlab_ci",
        "Jenkinsfile":       "jenkins",
        ".circleci":         "circleci",
        "bitbucket-pipelines.yml": "bitbucket",
        ".travis.yml":       "travis",
    }
    return [name for path_str, name in ci_files.items() if (Path(path) / path_str).exists()]


# ── Funções auxiliares para o fallback heurístico ─────────────────────────


def classify_signals(signals: dict) -> dict:
    """
    Classifica os sinais em categorias de negócio.
    Retorna dict com flags de alto nível usadas pelo fallback heurístico.
    """
    all_deps = {
        d.lower()
        for deps in signals.get("dependencies", {}).values()
        for d in deps
    }
    env_vars_str = " ".join(signals.get("env_vars", []))
    models = {m.lower() for m in signals.get("code_patterns", {}).get("model_names", [])}
    routes = {r.lower() for r in signals.get("code_patterns", {}).get("route_patterns", [])}
    sensitive = set(signals.get("code_patterns", {}).get("sensitive_fields", []))

    is_financial = bool(
        all_deps & _FINANCIAL_DEPS
        or any(kw in env_vars_str for kw in ("stripe", "payment", "billing", "invoice"))
        or any(r in routes for r in ("/payment", "/checkout", "/billing", "/subscription"))
        or {"payment", "invoice", "transaction", "billing"} & models
    )

    is_health = bool(
        all_deps & _HEALTH_DEPS
        or any(r in routes for r in ("/patient", "/record", "/health", "/medical"))
        or {"patient", "record", "claim", "policy", "beneficiary"} & models
        or {"medical_record", "patient_id", "diagnosis", "prescription"} & sensitive
    )

    is_pii = bool(
        is_financial
        or is_health
        or all_deps & _PII_DEPS
        or {"user", "customer", "account", "employee"} & models
        or {"cpf", "cnpj", "ssn", "date_of_birth", "dob"} & sensitive
        or any(kw in env_vars_str for kw in ("email", "sms", "sendgrid", "twilio"))
    )

    is_internet_facing = bool(
        signals.get("frameworks")
        or any(kw in env_vars_str for kw in ("api_key", "cors", "public", "frontend"))
        or any(r in routes for r in ("/api/v", "/auth", "/login"))
    )

    return {
        "is_financial": is_financial,
        "is_health": is_health,
        "is_pii": is_pii,
        "is_internet_facing": is_internet_facing,
        "all_deps": all_deps,
        "models": models,
        "routes": routes,
        "sensitive_fields": sensitive,
    }
