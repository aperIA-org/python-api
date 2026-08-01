"""Validação do alvo DAST de um repositório (``Repository.target_url``).

Isto **não** é validação de formato: é uma regra de segurança do domínio.
Um scan DAST (ZAP no Tier 3) não lê a URL — ele *ataca* a URL: spider,
depois active scan, disparando payloads reais de SQLi, XSS, path traversal
e afins contra tudo que encontrar. Duas consequências decorrem disso, e as
duas são responsabilidade nossa:

1. **Ataque a terceiros.** Se qualquer URL for aceita, um usuário cadastra
   ``https://banco-alheio.com.br`` e o aperIA passa a ser a origem de um
   ataque não autorizado — com o IP da nossa infraestrutura no log da
   vítima. O produto vira uma botnet de DAST sob demanda.
2. **SSRF com a credencial da infraestrutura.** Se o alvo for interno, o
   worker de Tier 3 alcança o que a rede dele alcança e o usuário não:
   ``http://localhost:8090`` (o próprio ZAP), ``http://10.0.0.5`` (banco,
   Redis), e sobretudo ``http://169.254.169.254`` — o endpoint de metadata
   de AWS/GCP/Azure, que devolve **credenciais IAM temporárias da máquina**
   e cujo conteúdo voltaria para o usuário dentro dos findings do relatório.

Por isso o alvo é restrito a URLs http/https absolutas apontando para hosts
públicos. O bloqueio vive no domínio (stdlib pura, sem framework) porque é
invariante da entidade ``Repository``, não detalhe da camada HTTP: qualquer
caminho de escrita futuro (importador, CLI, seed) herda a mesma regra.

**Limite conhecido e deliberado:** não resolvemos DNS aqui. Um domínio
público que aponta para ``127.0.0.1`` (DNS rebinding) passa nesta validação.
Resolver no momento do cadastro não resolveria — o registro DNS pode mudar
entre a validação e o scan (TOCTOU), então a checagem daria falsa sensação
de segurança e ainda custaria uma consulta de rede numa rota HTTP. A defesa
correta para esse vetor é de rede: egress policy no container do ZAP,
negando saída para RFC1918/link-local. Esta função cobre o que é decidível
localmente: esquema, forma e alvos literais internos.
"""

from __future__ import annotations

import ipaddress
from urllib.parse import urlsplit

TARGET_URL_MAX_LENGTH = 2048
"""Teto de tamanho. A coluna é ``Text``, mas URL de deploy não passa disso."""

_ESQUEMAS_PERMITIDOS = frozenset({"http", "https"})

# Nomes que resolvem para dentro por convenção, sem serem literais de IP.
_HOSTS_BLOQUEADOS = frozenset({"localhost", "ip6-localhost", "ip6-loopback"})
_SUFIXOS_BLOQUEADOS = (
    ".localhost",
    ".local",  # mDNS/Bonjour
    ".internal",  # inclui metadata.google.internal
    ".home.arpa",
    ".lan",
)

# RFC 6598 (CGNAT). Não é `is_private` no ipaddress, mas também não é
# endereçável na internet pública — é rede de operadora/infra.
_REDES_EXTRA_BLOQUEADAS = (
    ipaddress.ip_network("100.64.0.0/10"),
)


class TargetUrlInvalidaError(ValueError):
    """URL de aplicação recusada.

    ``codigo`` é estável e serve de contrato para o front-end (vira o
    ``type`` do erro 422); ``mensagem`` é o texto em português exibível ao
    usuário.
    """

    def __init__(self, codigo: str, mensagem: str) -> None:
        super().__init__(mensagem)
        self.codigo = codigo
        self.mensagem = mensagem


def _ip_de_hostname(hostname: str) -> ipaddress.IPv4Address | ipaddress.IPv6Address | None:
    """Interpreta o hostname como literal de IP, ou devolve ``None``.

    Cobre as formas alternativas que ``ipaddress`` sozinho recusa mas que o
    resolver do sistema aceita: decimal (``2130706433``) e hexadecimal
    (``0x7f000001``) são o mesmo ``127.0.0.1`` para ``curl``, e passariam
    como "nome de host" se olhássemos só o formato pontilhado.
    """
    try:
        return ipaddress.ip_address(hostname)
    except ValueError:
        pass

    inteiro: int | None = None
    if hostname.isdigit():
        inteiro = int(hostname)
    elif hostname.startswith(("0x", "0X")):
        try:
            inteiro = int(hostname, 16)
        except ValueError:
            return None
    if inteiro is None or not (0 <= inteiro <= 0xFFFFFFFF):
        return None
    return ipaddress.ip_address(inteiro)


def _ip_e_interno(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    """Diz se o IP pertence a alguma faixa que não deve ser alvo de DAST.

    ``is_private`` do ``ipaddress`` já cobre loopback (127/8, ::1), RFC1918
    (10/8, 172.16/12, 192.168/16), link-local (169.254/16 — inclusive o
    ``169.254.169.254`` de metadata) e ULA IPv6 (fc00::/7); as demais
    checagens estão explícitas porque a intenção de cada uma importa mais
    que a economia de linhas.
    """
    mapeado = getattr(ip, "ipv4_mapped", None)
    if mapeado is not None:
        # ``::ffff:127.0.0.1`` não é loopback como IPv6 — desembrulha antes.
        ip = mapeado
    if (
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    ):
        return True
    return any(ip in rede for rede in _REDES_EXTRA_BLOQUEADAS)


def validar_target_url(valor: object, *, permitir_alvo_interno: bool = False) -> str:
    """Valida a URL de aplicação e devolve a forma normalizada (sem espaços).

    Levanta ``TargetUrlInvalidaError`` — quem chama traduz para 422.

    ``permitir_alvo_interno`` libera **apenas** as recusas de rede interna
    (loopback, RFC1918, link-local, sufixos internos, host de rótulo único).
    Esquema, credenciais embutidas, tamanho e formato continuam validados —
    a flag não é um "aceite qualquer coisa".

    Existe por uma lacuna real: sem ela **não há caminho suportado para testar
    DAST em desenvolvimento**. Um alvo local é `http://juice-shop:3000` ou
    `localhost`, exatamente o que a proteção recusa. O default é ``False``, e a
    decisão de ligar fica com quem opera (``ALLOW_INTERNAL_DAST_TARGETS``) —
    nunca em produção, onde alvo interno significa usar o aperIA para atacar a
    própria infraestrutura.

    O parâmetro é explícito em vez de lido de ``settings`` porque este módulo é
    domínio puro: a regra não muda, quem decide o contexto é a borda.
    """
    if not isinstance(valor, str):
        raise TargetUrlInvalidaError(
            "target_url_malformada",
            "URL invalida: informe um texto com a URL da aplicacao publicada.",
        )

    url = valor.strip()
    if not url:
        raise TargetUrlInvalidaError(
            "target_url_vazia",
            "Informe a URL da aplicacao publicada, ou envie null para remover.",
        )
    if len(url) > TARGET_URL_MAX_LENGTH:
        raise TargetUrlInvalidaError(
            "target_url_muito_longa",
            f"URL longa demais (maximo {TARGET_URL_MAX_LENGTH} caracteres).",
        )

    try:
        partes = urlsplit(url)
        hostname = partes.hostname
        partes.port  # noqa: B018 — porta fora de faixa só estoura ao ser lida
    except ValueError as exc:
        raise TargetUrlInvalidaError(
            "target_url_malformada",
            "URL invalida: informe uma URL absoluta, como https://staging.suaempresa.com.",
        ) from exc

    esquema = (partes.scheme or "").lower()
    if not esquema:
        raise TargetUrlInvalidaError(
            "target_url_malformada",
            "URL invalida: informe uma URL absoluta, como https://staging.suaempresa.com.",
        )
    # Esquema antes de netloc: ``file:///etc/passwd`` e ``javascript:alert(1)``
    # não têm netloc, mas o motivo útil para o usuário é o esquema.
    if esquema not in _ESQUEMAS_PERMITIDOS:
        raise TargetUrlInvalidaError(
            "target_url_esquema_invalido",
            f"Esquema '{esquema}' nao e aceito: use http:// ou https://.",
        )
    if not partes.netloc:
        raise TargetUrlInvalidaError(
            "target_url_malformada",
            "URL invalida: informe uma URL absoluta, como https://staging.suaempresa.com.",
        )
    if partes.username or partes.password:
        raise TargetUrlInvalidaError(
            "target_url_com_credenciais",
            "Remova usuario e senha da URL: credenciais nao podem ser "
            "armazenadas no alvo do scan.",
        )
    if not hostname:
        raise TargetUrlInvalidaError(
            "target_url_malformada",
            "URL invalida: informe uma URL absoluta, como https://staging.suaempresa.com.",
        )

    host = hostname.lower().rstrip(".")
    ip = _ip_de_hostname(host)
    if ip is not None:
        if not permitir_alvo_interno and _ip_e_interno(ip):
            raise TargetUrlInvalidaError(
                "target_url_alvo_bloqueado",
                f"Alvo bloqueado: {host} aponta para a rede interna. "
                "Informe a URL publica do ambiente de staging/preview.",
            )
        return url

    if not permitir_alvo_interno and (
        host in _HOSTS_BLOQUEADOS or host.endswith(_SUFIXOS_BLOQUEADOS)
    ):
        raise TargetUrlInvalidaError(
            "target_url_alvo_bloqueado",
            f"Alvo bloqueado: {host} aponta para a rede interna. "
            "Informe a URL publica do ambiente de staging/preview.",
        )
    if not permitir_alvo_interno and "." not in host:
        # Host de rótulo único (``http://zap``, ``http://api-interna``) só
        # resolve dentro da rede do worker — na internet pública não existe.
        raise TargetUrlInvalidaError(
            "target_url_host_sem_dominio",
            f"Alvo bloqueado: '{host}' nao e um dominio publico. "
            "Informe o dominio completo, como staging.suaempresa.com.",
        )
    return url
