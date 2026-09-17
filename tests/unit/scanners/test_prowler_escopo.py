"""Escopo do Prowler quando nao existe diff.

Regressao: `has_iac_files` decide pelo DIFF, e num scan manual de branch
(`base_sha == commit_sha`) o diff e vazio. A condicao era sempre falsa e o
Prowler nunca rodava, mesmo num repositorio cheio de IaC. Medido no repo-alvo:
`infra/terraform/main.tf`, `infra/k8s/deployment.yaml` e `Dockerfile` presentes,
Prowler `skipped`.
"""
import pytest

from app.infrastructure.scanners.prowler_scanner import arvore_tem_iac, has_iac_files


class TestHasIacFiles:
    def test_diff_com_terraform(self):
        assert has_iac_files(["app/main.py", "infra/main.tf"])

    def test_diff_com_dockerfile(self):
        assert has_iac_files(["Dockerfile"])

    def test_diff_sem_iac(self):
        assert not has_iac_files(["app/main.py", "README.md"])

    def test_diff_vazio_e_falso(self):
        """E por isso que o fallback precisa existir."""
        assert not has_iac_files([])


class TestArvoreTemIac:
    def test_acha_terraform_em_subdiretorio(self, tmp_path):
        (tmp_path / "infra" / "terraform").mkdir(parents=True)
        (tmp_path / "infra" / "terraform" / "main.tf").write_text("resource {}")
        assert arvore_tem_iac(str(tmp_path))

    def test_acha_dockerfile_na_raiz(self, tmp_path):
        (tmp_path / "Dockerfile").write_text("FROM python")
        assert arvore_tem_iac(str(tmp_path))

    def test_acha_manifesto_k8s(self, tmp_path):
        (tmp_path / "k8s").mkdir()
        (tmp_path / "k8s" / "deployment.yaml").write_text("kind: Deployment")
        assert arvore_tem_iac(str(tmp_path))

    def test_arvore_sem_iac(self, tmp_path):
        (tmp_path / "app.py").write_text("print(1)")
        (tmp_path / "README.md").write_text("# doc")
        assert not arvore_tem_iac(str(tmp_path))

    def test_ignora_git(self, tmp_path):
        """A arvore materializada inclui `.git`, e um `.yaml` la dentro nao e
        infraestrutura de ninguem — mesmo motivo pelo qual o TruffleHog exclui."""
        objetos = tmp_path / ".git" / "objects"
        objetos.mkdir(parents=True)
        (objetos / "algo.yaml").write_text("nao sou iac")
        assert not arvore_tem_iac(str(tmp_path))

    def test_diretorio_vazio(self, tmp_path):
        assert not arvore_tem_iac(str(tmp_path))
