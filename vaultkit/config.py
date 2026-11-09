"""Configuração do framework (lida de variáveis de ambiente ou passada em código)."""

from __future__ import annotations

import os
from dataclasses import dataclass, field, replace
from typing import Mapping

from .errors import ConfigurationError


def _bool(value: str | None, default: bool = False) -> bool:
    if value is None or value == "":
        return default
    return value.strip().lower() in {"1", "true", "yes", "sim", "on"}


@dataclass(frozen=True)
class VaultConfig:
    """Parâmetros de conexão.

    ``provider`` escolhe a estratégia (``openbao``, ``vault`` ou ``gateway``);
    trocar de cofre é trocar este valor, não reescrever a aplicação.
    """

    provider: str = "openbao"
    address: str = "http://127.0.0.1:8210"
    namespace: str | None = None
    kv_mount: str = "secret"
    auth_method: str = "approle"  # "approle" | "token"
    auth_mount: str = "approle"
    token: str | None = field(default=None, repr=False)
    role_id: str | None = field(default=None, repr=False)
    secret_id: str | None = field(default=None, repr=False)
    gateway_url: str = "http://127.0.0.1:8800"
    timeout: float = 10.0
    verify_tls: bool | str = True
    allow_http: bool = False
    cache_ttl: float = 60.0
    verbose: bool = False
    client_name: str = "vaultkit"

    # ------------------------------------------------------------------ #
    @classmethod
    def from_env(cls, env: Mapping[str, str] | None = None, prefix: str = "VAULTKIT_") -> "VaultConfig":
        """Monta a configuração a partir de ``VAULTKIT_*`` (ou do ``env`` passado)."""
        e = os.environ if env is None else env

        def g(name: str, default: str | None = None) -> str | None:
            return e.get(prefix + name, default)

        verify: bool | str = g("CA_CERT") or _bool(g("VERIFY_TLS"), True)
        return cls(
            provider=g("PROVIDER", "openbao") or "openbao",
            address=(g("ADDR", cls.address) or cls.address).rstrip("/"),
            namespace=g("NAMESPACE") or None,
            kv_mount=g("KV_MOUNT", "secret") or "secret",
            auth_method=g("AUTH_METHOD", "approle") or "approle",
            auth_mount=g("AUTH_MOUNT", "approle") or "approle",
            token=g("TOKEN") or None,
            role_id=g("ROLE_ID") or None,
            secret_id=g("SECRET_ID") or None,
            gateway_url=(g("GATEWAY_URL", cls.gateway_url) or cls.gateway_url).rstrip("/"),
            timeout=float(g("TIMEOUT", "10") or 10),
            verify_tls=verify,
            allow_http=_bool(g("ALLOW_HTTP")),
            cache_ttl=float(g("CACHE_TTL", "60") or 60),
            verbose=_bool(g("VERBOSE")),
            client_name=g("CLIENT_NAME", "vaultkit") or "vaultkit",
        )

    def with_overrides(self, **kwargs) -> "VaultConfig":
        """Cópia com campos alterados (a configuração é imutável)."""
        return replace(self, **kwargs)

    def validate(self) -> "VaultConfig":
        """Confere coerência mínima antes de qualquer chamada de rede.

        :raises ConfigurationError: quando falta credencial ou o endereço é
            ``http://`` sem ``allow_http`` (TLS é obrigatório fora do laboratório).
        """
        url = self.gateway_url if self.provider == "gateway" else self.address
        if not url.startswith(("http://", "https://")):
            raise ConfigurationError(f"endereço inválido: {url!r}")
        if url.startswith("http://") and not self.allow_http:
            raise ConfigurationError(
                "endereço http:// recusado; use https:// ou VAULTKIT_ALLOW_HTTP=true (apenas laboratório)"
            )
        if self.auth_method == "approle" and not (self.role_id and self.secret_id):
            raise ConfigurationError("auth_method=approle exige role_id e secret_id")
        if self.auth_method == "token" and not self.token:
            raise ConfigurationError("auth_method=token exige token")
        if self.auth_method not in {"approle", "token"}:
            raise ConfigurationError(f"auth_method desconhecido: {self.auth_method!r}")
        return self


def load_env_file(path: str, override: bool = False) -> dict[str, str]:
    """Carrega um arquivo ``CHAVE=valor`` em ``os.environ`` (sem dependências externas).

    Linhas vazias e comentários (``#``) são ignorados. Devolve o que foi lido.
    """
    values: dict[str, str] = {}
    if not os.path.exists(path):
        return values
    with open(path, encoding="utf-8") as fh:
        for line in fh:
            line = line.strip()
            if not line or line.startswith("#") or "=" not in line:
                continue
            k, v = line.split("=", 1)
            k, v = k.strip().removeprefix("export "), v.strip().strip('"').strip("'")
            values[k] = v
            if override or k not in os.environ:
                os.environ[k] = v
    return values
