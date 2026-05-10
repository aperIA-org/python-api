"""
Testes unitários para extração de sinais de repositório.
Usa arquivos temporários em disco — sem mocks de filesystem.
"""
import json
import tempfile
from pathlib import Path

import pytest

from infrastructure.analysis._repo_signals import (
    classify_signals,
    extract_repo_signals,
    _get_dependencies,
    _get_env_vars,
    _get_code_patterns,
    _detect_frameworks,
    _has_migrations,
)


def _write(tmp: Path, rel: str, content: str) -> None:
    fp = tmp / rel
    fp.parent.mkdir(parents=True, exist_ok=True)
    fp.write_text(content, encoding="utf-8")


class TestGetDependencies:
    def test_parses_requirements_txt(self, tmp_path):
        _write(tmp_path, "requirements.txt", "fastapi==0.115.0\nstripe>=5.0\n# comment\n-r base.txt\n")
        deps = _get_dependencies(tmp_path)
        assert "fastapi" in deps["python"]
        assert "stripe" in deps["python"]

    def test_parses_package_json(self, tmp_path):
        pkg = {"dependencies": {"express": "^4.18", "stripe": "^12"}, "devDependencies": {"jest": "^29"}}
        _write(tmp_path, "package.json", json.dumps(pkg))
        deps = _get_dependencies(tmp_path)
        assert "express" in deps["node"]
        assert "stripe" in deps["node"]
        assert "jest" in deps["node"]

    def test_returns_empty_when_no_dep_files(self, tmp_path):
        deps = _get_dependencies(tmp_path)
        assert deps == {}

    def test_ignores_commented_and_options_lines(self, tmp_path):
        _write(tmp_path, "requirements.txt", "# comment\n-r other.txt\ngit+https://...\nrequests==2.31\n")
        deps = _get_dependencies(tmp_path)
        assert "requests" in deps["python"]
        assert len([d for d in deps["python"] if d.startswith("-")]) == 0


class TestGetEnvVars:
    def test_extracts_keys_from_env_example(self, tmp_path):
        _write(tmp_path, ".env.example", "DATABASE_URL=\nSTRIPE_KEY=sk-xxx\n# comment\nANTHROPIC_API_KEY=\n")
        keys = _get_env_vars(tmp_path)
        assert "database_url" in keys
        assert "stripe_key" in keys
        assert "anthropic_api_key" in keys

    def test_returns_empty_when_no_env_file(self, tmp_path):
        assert _get_env_vars(tmp_path) == []

    def test_skips_comment_lines(self, tmp_path):
        _write(tmp_path, ".env.example", "# this is a comment\nKEY=value\n")
        keys = _get_env_vars(tmp_path)
        assert len(keys) == 1
        assert keys[0] == "key"


class TestGetCodePatterns:
    def test_detects_user_model(self, tmp_path):
        _write(tmp_path, "models/user.py", "class User(Base):\n    id = Column(UUID)\n    email = Column(String)\n")
        patterns = _get_code_patterns(tmp_path)
        assert "User" in patterns["model_names"]

    def test_detects_payment_model(self, tmp_path):
        _write(tmp_path, "models/payment.py", "class Payment(Base):\n    amount = Column(Numeric)\n")
        patterns = _get_code_patterns(tmp_path)
        assert "Payment" in patterns["model_names"]

    def test_detects_auth_route(self, tmp_path):
        _write(tmp_path, "routes/auth.py", 'router.get("/auth/login", handler)\nrouter.post("/auth/register", h)\n')
        patterns = _get_code_patterns(tmp_path)
        assert any("/auth" in r or "auth" in r.lower() for r in patterns["route_patterns"])

    def test_detects_sensitive_field_cpf(self, tmp_path):
        _write(tmp_path, "models/customer.py", "class Customer:\n    cpf = db.Column(String(11))\n    name = db.Column(String)\n")
        patterns = _get_code_patterns(tmp_path)
        assert "cpf" in patterns["sensitive_fields"]

    def test_detects_credit_card_field(self, tmp_path):
        _write(tmp_path, "models/payment.py", "    credit_card = encrypted_column(String)\n")
        patterns = _get_code_patterns(tmp_path)
        assert "credit_card" in patterns["sensitive_fields"]

    def test_skips_node_modules(self, tmp_path):
        _write(tmp_path, "node_modules/some_lib/index.js", "class User { constructor() {} }")
        patterns = _get_code_patterns(tmp_path)
        # node_modules is excluded — User should NOT be in model_names
        assert "User" not in patterns["model_names"]


class TestDetectFrameworks:
    def test_detects_fastapi(self):
        deps = {"python": ["fastapi", "uvicorn", "sqlalchemy"]}
        frameworks = _detect_frameworks(deps)
        assert "web_api" in frameworks

    def test_detects_react_as_frontend(self):
        deps = {"node": ["react", "react-dom", "webpack"]}
        frameworks = _detect_frameworks(deps)
        assert "frontend" in frameworks

    def test_detects_celery_as_pipeline(self):
        deps = {"python": ["celery", "redis", "kombu"]}
        frameworks = _detect_frameworks(deps)
        assert "data_pipeline" in frameworks

    def test_returns_empty_for_unknown_deps(self):
        deps = {"python": ["requests", "click", "pydantic"]}
        frameworks = _detect_frameworks(deps)
        assert frameworks == []


class TestHasMigrations:
    def test_detects_alembic_dir(self, tmp_path):
        (tmp_path / "alembic").mkdir()
        assert _has_migrations(tmp_path) is True

    def test_detects_migrations_dir(self, tmp_path):
        (tmp_path / "migrations").mkdir()
        assert _has_migrations(tmp_path) is True

    def test_returns_false_when_no_migrations(self, tmp_path):
        assert _has_migrations(tmp_path) is False


class TestClassifySignals:
    def test_financial_from_stripe_dep(self, tmp_path):
        _write(tmp_path, "requirements.txt", "stripe==5.0\nfastapi==0.115.0\n")
        signals = extract_repo_signals(str(tmp_path))
        flags = classify_signals(signals)
        assert flags["is_financial"] is True
        assert flags["is_pii"] is True  # financial implica PII

    def test_health_from_model_name(self, tmp_path):
        _write(tmp_path, "models.py", "class Patient(Base):\n    medical_record = Column(String)\n")
        signals = extract_repo_signals(str(tmp_path))
        flags = classify_signals(signals)
        assert flags["is_health"] is True

    def test_pii_from_cpf_field(self, tmp_path):
        _write(tmp_path, "models.py", "class Customer:\n    cpf = db.Column(String(11))\n")
        signals = extract_repo_signals(str(tmp_path))
        flags = classify_signals(signals)
        assert flags["is_pii"] is True

    def test_internet_facing_from_framework(self, tmp_path):
        _write(tmp_path, "requirements.txt", "fastapi==0.115.0\n")
        signals = extract_repo_signals(str(tmp_path))
        flags = classify_signals(signals)
        assert flags["is_internet_facing"] is True
