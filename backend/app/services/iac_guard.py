"""Guard de SSRF e path traversal do IaC scan (US-01.19).

`validate_repo_url`: esquema https/git, host na allowlist (`IAC_ALLOWED_HOSTS`)
e resolução DNS bloqueando faixas privadas — o worker não pode virar proxy da
rede interna nem alcançar o metadata service (169.254.169.254).
`confine_scan_path`: `path` resolvido e confinado ao diretório do clone —
`..` e symlinks escapando → erro, o Checkov não lê nada fora do clone.

O guard roda na API (422 no trigger) **e** no worker (defesa em profundidade:
a task falha visivelmente se algo burlar a primeira camada).
"""

from __future__ import annotations

import ipaddress
import socket
from pathlib import Path
from urllib.parse import urlparse

from app.core.config import settings


class IacScanRejectedError(ValueError):
    """repo_url/path rejeitados pelo guard — nunca chegar ao clone/leitura."""


def _is_publicly_routable(ip: ipaddress.IPv4Address | ipaddress.IPv6Address) -> bool:
    return not (
        ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_reserved or ip.is_multicast or ip.is_unspecified
    )


def resolve_host_safely(host: str) -> list[str]:
    """Resolve o host e retorna os IPs; rejeita se qualquer registro cair em
    faixa não roteável (RFC1918, loopback, link-local, reserved)."""
    try:
        records = socket.getaddrinfo(host, None)
    except socket.gaierror as exc:
        raise IacScanRejectedError(f"repo host '{host}' does not resolve") from exc
    ips = {record[4][0] for record in records}
    bad = [ip for ip in ips if not _is_publicly_routable(ipaddress.ip_address(ip))]
    if bad:
        raise IacScanRejectedError(f"repo host '{host}' resolves to non-routable address(es): {', '.join(sorted(bad))}")
    return sorted(ips)


def validate_repo_url(repo_url: str) -> str:
    """Valida `repo_url` para o clone: esquema, host na allowlist e DNS público."""
    parsed = urlparse(repo_url or "")
    if parsed.scheme == "https":
        host = parsed.hostname
    elif parsed.scheme == "ssh" or repo_url.startswith("git@"):
        # git@github.com:org/repo.git e ssh://git@host/path
        host = parsed.hostname or (repo_url.split("git@", 1)[-1].split(":", 1)[0].split("/", 1)[0])
    else:
        raise IacScanRejectedError("repo_url must use https://, ssh:// or git@user@host:repo form")
    if not host:
        raise IacScanRejectedError("repo_url has no resolvable host")

    allowed = {h.lower() for h in settings.IAC_ALLOWED_HOSTS}
    if host.lower() not in allowed:
        raise IacScanRejectedError(f"repo host '{host}' is not in IAC_ALLOWED_HOSTS ({', '.join(sorted(allowed))})")
    resolve_host_safely(host)
    return repo_url


def confine_scan_path(clone_dest: Path, path: str) -> Path:
    """Resolve `path` contra o clone e garante que não escapa do clone dir."""
    base = clone_dest.resolve()
    candidate = (base / path).resolve()
    if not candidate.is_relative_to(base):
        raise IacScanRejectedError(f"scan path '{path}' escapes the clone directory")
    return candidate
