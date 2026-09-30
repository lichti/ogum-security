"""OIDC por tenant (US-06.01 — Epic 06 Sprint 2).

Fluxo authorization code com PKCE-less clients confidenciais: o Client
Secret vive no Vault (`secret/tenants/{tenant_id}/oidc` — mesma convenção de
paths dos providers, US-06.11) e os metadados no ArangoDB (coleção
`oidc_config` no database do tenant, um único doc `_key: "idp"`).

O `id_token` do IdP é validado por JWKS (RS256/ES256), `iss`, `aud`, `exp` e
`nonce`; o JWT interno do Ogum continua HS256 (security.py) — o IdP nunca
assina tokens que a API aceita. Grupos do IdP mapeiam para `Role` via tabela
do tenant; sem match, `default_role` (nunca PlatformAdmin por omissão).

SSRF: a `discovery_url` é input de PlatformAdmin, mas a validação segue o
precedente da US-01.19 — https obrigatório em produção, DNS resolvido e
faixas privadas rejeitadas antes de qualquer fetch.
"""

from __future__ import annotations

import ipaddress
import logging
import socket
import time
from functools import lru_cache
from typing import Any, cast
from urllib.parse import urlsplit

import httpx
from arango.database import StandardDatabase
from jose import JWSError, JWTError, jwk, jwt
from pydantic import BaseModel, Field, field_validator

from app.core.config import settings
from app.core.rbac import Role
from app.services import vault_client
from app.services.tenant_registry import validate_tenant_id

logger = logging.getLogger(__name__)

COLLECTION = "oidc_config"
DOC_KEY = "idp"
STATE_TTL_SECONDS = 600
_JWKS_CACHE_TTL = 3600.0

_SUPPORTED_SCOPES = "openid email profile groups"
_REQUIRED_DISCOVERY_FIELDS = ("issuer", "authorization_endpoint", "token_endpoint", "jwks_uri")


class RoleMapping(BaseModel):
    group: str = Field(..., min_length=1, max_length=200)
    role: Role


class OidcConfig(BaseModel):
    """Metadados do IdP — o Client Secret nunca passa por aqui."""

    idp_name: str = Field("OIDC", max_length=60)
    discovery_url: str = Field(..., min_length=8, max_length=2048)
    client_id: str = Field(..., min_length=1, max_length=256)
    scopes: str = _SUPPORTED_SCOPES
    group_claim_key: str = Field("groups", max_length=60)
    default_role: Role = Role.SecOps
    role_mappings: list[RoleMapping] = Field(default_factory=list)

    @field_validator("discovery_url")
    @classmethod
    def _https_in_production(cls, value: str) -> str:
        if settings.APP_ENV == "production" and not value.startswith("https://"):
            raise ValueError("discovery_url must use https in production")
        return value


class DiscoveryError(ValueError):
    """Discovery inacessível, malformado ou apontando para rede privada."""


def load_config(db: StandardDatabase) -> OidcConfig | None:
    """Config do IdP do tenant — None se o tenant ainda não configurou OIDC."""
    if not db.has_collection(COLLECTION):
        return None
    doc = db.collection(COLLECTION).get(DOC_KEY)
    if not doc:
        return None
    return OidcConfig.model_validate(doc)


def save_config(
    db: StandardDatabase,
    tenant_id: str,
    config: OidcConfig,
    client_secret: str,
) -> OidcConfig:
    """Persiste metadados no ArangoDB e o secret no Vault (US-06.11 paths)."""
    validate_tenant_id(tenant_id)
    vault_client.store_credentials(tenant_id, "oidc", {"client_secret": client_secret})
    col = db.collection(COLLECTION) if db.has_collection(COLLECTION) else db.create_collection(COLLECTION)
    doc = {"_key": DOC_KEY, **config.model_dump(mode="json")}
    col.insert(doc, overwrite_mode="replace")
    logger.info("OIDC config saved for tenant %s (idp=%s)", tenant_id, config.idp_name)
    return config


def load_client_secret(tenant_id: str) -> str:
    secrets = vault_client.load_credentials(vault_client.tenant_secret_path(tenant_id, "oidc"))
    secret = secrets.get("client_secret")
    if not secret:
        raise ValueError("OIDC client_secret missing in Vault")
    return str(secret)


# ── Discovery ────────────────────────────────────────────────────────────────


def _http() -> httpx.Client:
    """Ponto de injeção para testes (monkeypatch → httpx.MockTransport)."""
    return httpx.Client(timeout=10.0)


def _assert_public_host(url: str) -> None:
    """Rejeita scheme não-https (em produção) e hosts em faixas privadas."""
    parts = urlsplit(url)
    if parts.scheme != "https" and settings.APP_ENV == "production":
        raise DiscoveryError("discovery endpoint must use https in production")
    host = parts.hostname or ""
    try:
        infos = {info[4][0] for info in socket.getaddrinfo(host, None)}
    except OSError as exc:
        raise DiscoveryError(f"cannot resolve discovery host {host!r}") from exc
    for ip in infos:
        if ipaddress.ip_address(ip).is_private or ipaddress.ip_address(ip).is_loopback:
            raise DiscoveryError(f"discovery host {host!r} resolves to a private address ({ip})")


def fetch_discovery(discovery_url: str) -> dict[str, Any]:
    """`GET {discovery_url}/.well-known/openid-configuration` com validação
    SSRF (US-01.19 precedent) e dos campos obrigatórios do padrão."""
    base = discovery_url.rstrip("/")
    if base.endswith("/.well-known/openid-configuration"):
        url = base
    else:
        url = f"{base}/.well-known/openid-configuration"
    _assert_public_host(url)
    # Apontar ao IdP próprio é a função da feature — a URL é de PlatformAdmin e
    # passa pela validação acima (https em produção, DNS resolvido e faixas
    # privadas/loopback rejeitadas, precedente US-01.19).
    # codeql[py/full-ssrf]
    response = _http().get(url)
    try:
        response.raise_for_status()
        doc = cast(dict[str, Any], response.json())
    except (httpx.HTTPError, ValueError) as exc:
        raise DiscoveryError(f"discovery endpoint failed: {exc}") from exc
    missing = [field for field in _REQUIRED_DISCOVERY_FIELDS if not doc.get(field)]
    if missing:
        raise DiscoveryError(f"discovery document missing fields: {', '.join(missing)}")
    return doc


def validate_discovery(discovery_url: str) -> dict[str, Any]:
    """Gate do POST /config — o endpoint tem que responder ANTES de salvar."""
    return fetch_discovery(discovery_url)


# ── Token exchange + id_token ────────────────────────────────────────────────


def exchange_code(
    discovery: dict[str, Any],
    config: OidcConfig,
    code: str,
    client_secret: str,
    redirect_uri: str,
) -> dict[str, Any]:
    """Troca o authorization code pelos tokens do IdP (POST token_endpoint)."""
    try:
        response = _http().post(
            discovery["token_endpoint"],
            data={
                "grant_type": "authorization_code",
                "code": code,
                "redirect_uri": redirect_uri,
                "client_id": config.client_id,
                "client_secret": client_secret,
            },
            headers={"Content-Type": "application/x-www-form-urlencoded"},
        )
        response.raise_for_status()
        return cast(dict[str, Any], response.json())
    except httpx.HTTPError as exc:
        raise ValueError(f"token exchange failed: {exc}") from exc


@lru_cache(maxsize=8)
def _jwks_cache_key(jwks_uri: str, fetched_at_epoch: int) -> dict[str, Any]:
    """Chave de cache trivial — o TTL real fica em _load_jwks (fetched_at)."""
    response = _http().get(jwks_uri)
    response.raise_for_status()
    return dict(response.json())


def _load_jwks(jwks_uri: str) -> dict[str, Any]:
    _assert_public_host(jwks_uri)
    bucket = int(time.time() // _JWKS_CACHE_TTL)
    return _jwks_cache_key(jwks_uri, bucket)


def validate_id_token(
    id_token: str,
    discovery: dict[str, Any],
    config: OidcConfig,
    expected_nonce: str,
) -> dict[str, Any]:
    """Valida assinatura (JWKS), iss, aud, exp e nonce; devolve os claims."""
    algorithms = discovery.get("id_token_signing_alg_values_supported") or ["RS256"]
    try:
        jwks = _load_jwks(discovery["jwks_uri"])
        key = None
        try:
            unverified_header = jwt.get_unverified_header(id_token)
            for entry in jwks.get("keys", []):
                if entry.get("kid") == unverified_header.get("kid"):
                    key = jwk.construct(entry, unverified_header.get("alg"))
                    break
        except JWTError as exc:
            raise ValueError(f"malformed id_token header: {exc}") from exc
        if key is None:
            raise ValueError("id_token kid not found in JWKS")
        claims = cast(
            dict[str, Any],
            jwt.decode(
                id_token,
                key,
                algorithms=[str(alg) for alg in algorithms],
                audience=config.client_id,
                issuer=discovery["issuer"],
            ),
        )
    except (JWTError, JWSError, httpx.HTTPError) as exc:
        raise ValueError(f"id_token validation failed: {exc}") from exc
    if claims.get("nonce") != expected_nonce:
        raise ValueError("id_token nonce mismatch")
    return claims


def map_role(claims: dict[str, Any], config: OidcConfig) -> Role:
    """Grupos do IdP → Role Ogum pela tabela do tenant; sem match,
    `default_role`. PlatformAdmin só entra por mapping explícito."""
    raw_groups = claims.get(config.group_claim_key) or []
    if isinstance(raw_groups, str):
        raw_groups = [raw_groups]
    member_of = {str(group) for group in raw_groups}
    for mapping in config.role_mappings:
        if mapping.group in member_of:
            return mapping.role
    return config.default_role
