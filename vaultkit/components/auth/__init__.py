"""Componente de Autenticação.

Interface provida: :class:`IAuthenticator`, :class:`ITokenProvider`.
Interface requerida: ``IVaultTransport``.
"""

from __future__ import annotations

from ...config import VaultConfig
from ...errors import ConfigurationError
from ...http import IVaultTransport
from .approle import AppRoleAuthenticator, token_from_auth
from .interfaces import AuthToken, IAuthenticator, ITokenProvider
from .manager import TokenManager
from .token import StaticTokenAuthenticator, StaticTokenProvider


def create_authenticator(config: VaultConfig, transport: IVaultTransport) -> IAuthenticator:
    """Fábrica do componente: escolhe o método de login pela configuração."""
    if config.auth_method == "approle":
        return AppRoleAuthenticator(transport, config.role_id or "", config.secret_id or "", config.auth_mount)
    if config.auth_method == "token":
        return StaticTokenAuthenticator(transport, config.token or "")
    raise ConfigurationError(f"auth_method desconhecido: {config.auth_method!r}")


__all__ = [
    "AuthToken", "IAuthenticator", "ITokenProvider", "AppRoleAuthenticator",
    "StaticTokenAuthenticator", "StaticTokenProvider", "TokenManager",
    "create_authenticator", "token_from_auth",
]
