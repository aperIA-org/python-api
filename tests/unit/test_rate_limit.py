"""Limite por IP: conta certo, identifica o cliente certo e não derruba a API."""
import pytest
import redis as redis_lib
from fastapi import HTTPException

from app.infrastructure.security import rate_limit


class _RedisFake:
    def __init__(self, erro=None):
        self.contadores = {}
        self.expiracoes = {}
        self._erro = erro

    def incr(self, chave):
        if self._erro:
            raise self._erro
        self.contadores[chave] = self.contadores.get(chave, 0) + 1
        return self.contadores[chave]

    def expire(self, chave, segundos):
        self.expiracoes[chave] = segundos


class _RequestFake:
    def __init__(self, headers=None, host="10.0.0.1"):
        self.headers = headers or {}
        self.client = type("C", (), {"host": host})()


@pytest.fixture
def redis_fake(monkeypatch):
    fake = _RedisFake()
    monkeypatch.setattr(rate_limit, "_redis", lambda: fake)
    return fake


def test_bloqueia_ao_passar_do_maximo(redis_fake):
    req = _RequestFake()
    for _ in range(3):
        rate_limit.limitar(req, escopo="signup", maximo=3, janela_s=60)

    with pytest.raises(HTTPException) as exc:
        rate_limit.limitar(req, escopo="signup", maximo=3, janela_s=60)

    assert exc.value.status_code == 429
    assert exc.value.headers["Retry-After"] == "60"


def test_janela_expira_so_na_primeira(redis_fake):
    req = _RequestFake()
    for _ in range(3):
        rate_limit.limitar(req, escopo="signup", maximo=5, janela_s=60)
    # Renovar o TTL a cada tentativa deixaria o bloqueio eterno enquanto o
    # atacante insistisse, e a janela nunca zeraria para quem errou sem querer.
    assert redis_fake.expiracoes == {"ratelimit:signup:10.0.0.1": 60}


def test_contadores_sao_por_ip_e_por_escopo(redis_fake):
    rate_limit.limitar(_RequestFake(host="1.1.1.1"), escopo="login", maximo=5, janela_s=60)
    rate_limit.limitar(_RequestFake(host="2.2.2.2"), escopo="login", maximo=5, janela_s=60)
    rate_limit.limitar(_RequestFake(host="1.1.1.1"), escopo="signup", maximo=5, janela_s=60)
    assert redis_fake.contadores == {
        "ratelimit:login:1.1.1.1": 1,
        "ratelimit:login:2.2.2.2": 1,
        "ratelimit:signup:1.1.1.1": 1,
    }


class TestIpAtrasDoProxy:
    """Sem isto o limite vira um contador único para o mundo todo."""

    def test_usa_o_ultimo_do_xff_que_e_o_escrito_pelo_proxy(self):
        req = _RequestFake(headers={"x-forwarded-for": "203.0.113.9"}, host="172.18.0.5")
        assert rate_limit.ip_do_cliente(req) == "203.0.113.9"

    def test_ignora_ip_forjado_pelo_cliente_no_inicio_da_lista(self):
        # O cliente manda um XFF inventado; o Caddy acrescenta o IP real ao
        # final. Ler o primeiro item deixaria qualquer um trocar de "identidade"
        # a cada request e furar o limite.
        req = _RequestFake(headers={"x-forwarded-for": "1.2.3.4, 203.0.113.9"})
        assert rate_limit.ip_do_cliente(req) == "203.0.113.9"

    def test_sem_proxy_usa_o_socket(self):
        assert rate_limit.ip_do_cliente(_RequestFake(host="10.0.0.7")) == "10.0.0.7"


def test_redis_fora_do_ar_libera_a_requisicao(monkeypatch):
    """Preferir abuso a indisponibilidade: o login não pode cair com o Redis."""
    monkeypatch.setattr(
        rate_limit, "_redis", lambda: _RedisFake(erro=redis_lib.ConnectionError("fora"))
    )
    rate_limit.limitar(_RequestFake(), escopo="login", maximo=1, janela_s=60)
