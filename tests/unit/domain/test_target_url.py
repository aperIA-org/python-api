"""Validação do alvo de DAST (`Repository.target_url`).

O foco não é formato de URL, é superfície de ataque: cada caso bloqueado
aqui corresponde a um alvo que o worker de Tier 3 alcançaria de dentro da
nossa rede (SSRF) ou a um terceiro que seria atacado sem autorização.
"""

from __future__ import annotations

import pytest

from app.domain.github.target_url import (
    TARGET_URL_MAX_LENGTH,
    TargetUrlInvalidaError,
    validar_target_url,
)


class TestUrlsAceitas:
    @pytest.mark.parametrize(
        "url",
        [
            "https://staging.suaempresa.com",
            "http://staging.suaempresa.com",
            "https://preview-42.vercel.app/app",
            "https://staging.acme.com:8443/painel?debug=1#topo",
            "https://8.8.8.8/app",  # IP público literal é alvo legítimo
            "https://[2001:4860:4860::8888]/",
        ],
    )
    def test_url_publica_http_https_passa(self, url):
        assert validar_target_url(url) == url

    def test_espacos_em_volta_sao_removidos(self):
        assert validar_target_url("  https://staging.acme.com  ") == "https://staging.acme.com"


class TestFormaDaUrl:
    @pytest.mark.parametrize(
        "url",
        ["staging.acme.com", "//staging.acme.com", "https://", "não é url"],
    )
    def test_url_nao_absoluta_e_malformada(self, url):
        with pytest.raises(TargetUrlInvalidaError) as exc:
            validar_target_url(url)
        assert exc.value.codigo == "target_url_malformada"

    def test_valor_nao_texto_e_malformado(self):
        with pytest.raises(TargetUrlInvalidaError) as exc:
            validar_target_url(42)
        assert exc.value.codigo == "target_url_malformada"

    def test_string_vazia_pede_null(self):
        with pytest.raises(TargetUrlInvalidaError) as exc:
            validar_target_url("   ")
        assert exc.value.codigo == "target_url_vazia"
        assert "null" in exc.value.mensagem

    def test_url_longa_demais(self):
        url = "https://acme.com/" + "a" * TARGET_URL_MAX_LENGTH
        with pytest.raises(TargetUrlInvalidaError) as exc:
            validar_target_url(url)
        assert exc.value.codigo == "target_url_muito_longa"

    @pytest.mark.parametrize(
        "url",
        [
            "file:///etc/passwd",
            "javascript:alert(1)",
            "ftp://arquivos.acme.com",
            "gopher://acme.com:70/_x",
            "data:text/html,<script>x</script>",
        ],
    )
    def test_esquema_fora_de_http_https(self, url):
        with pytest.raises(TargetUrlInvalidaError) as exc:
            validar_target_url(url)
        assert exc.value.codigo == "target_url_esquema_invalido"

    def test_credenciais_embutidas_sao_recusadas(self):
        with pytest.raises(TargetUrlInvalidaError) as exc:
            validar_target_url("https://admin:senha@staging.acme.com")
        assert exc.value.codigo == "target_url_com_credenciais"

    def test_porta_fora_de_faixa(self):
        with pytest.raises(TargetUrlInvalidaError) as exc:
            validar_target_url("https://staging.acme.com:99999/")
        assert exc.value.codigo == "target_url_malformada"


class TestAlvosInternosBloqueados:
    """Um por um: cada URL aqui é um SSRF se passar."""

    @pytest.mark.parametrize(
        "url",
        [
            # localhost e loopback
            "http://localhost:3000",
            "http://LOCALHOST/app",
            "http://app.localhost/",
            "http://127.0.0.1:8090",  # o próprio container do ZAP
            "http://127.1.2.3/",  # 127.0.0.0/8 inteiro, não só o .1
            "https://[::1]/",
            # RFC1918
            "http://10.0.0.5/",
            "http://172.16.0.1/",
            "http://172.31.255.254/",
            "http://192.168.1.10/",
            # link-local + metadata de cloud (credenciais IAM da instância)
            "http://169.254.0.1/",
            "http://169.254.169.254/latest/meta-data/iam/security-credentials/",
            "https://[fe80::1]/",
            # ULA IPv6 e IPv4 mapeado em IPv6
            "http://[fc00::1]/",
            "http://[::ffff:127.0.0.1]/",
            "http://[::ffff:10.0.0.1]/",
            # CGNAT (RFC 6598)
            "http://100.64.0.1/",
            # 0.0.0.0 = "este host"
            "http://0.0.0.0:8080/",
            # formas alternativas do mesmo 127.0.0.1 que o resolver aceita
            "http://2130706433/",
            "http://0x7f000001/",
            # sufixos que só resolvem para dentro
            "http://api.local/",
            "http://banco.internal/",
            "http://metadata.google.internal/computeMetadata/v1/",
            "http://roteador.home.arpa/",
            "http://nas.lan/",
        ],
    )
    def test_alvo_interno_e_bloqueado(self, url):
        with pytest.raises(TargetUrlInvalidaError) as exc:
            validar_target_url(url)
        assert exc.value.codigo == "target_url_alvo_bloqueado"
        assert "rede interna" in exc.value.mensagem

    @pytest.mark.parametrize("url", ["http://zap:8090", "http://api-interna/", "http://redis"])
    def test_host_de_rotulo_unico_e_bloqueado(self, url):
        """Nome sem ponto só existe dentro da rede do worker."""
        with pytest.raises(TargetUrlInvalidaError) as exc:
            validar_target_url(url)
        assert exc.value.codigo == "target_url_host_sem_dominio"

    def test_ponto_final_nao_burla_o_sufixo(self):
        with pytest.raises(TargetUrlInvalidaError) as exc:
            validar_target_url("http://banco.internal./")
        assert exc.value.codigo == "target_url_alvo_bloqueado"
