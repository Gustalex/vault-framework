"""VaultKit — framework para conexão simplificada com cofres de segredos.

Uso mínimo::

    from vaultkit import SecretAccessFramework, VaultConfig

Componentes reutilizáveis ficam em :mod:`vaultkit.components`; as estratégias
de acesso a cada cofre, em :mod:`vaultkit.providers`.
"""

from .components.audit import AuditEvent, IAuditSink
from .components.cache import ISecretCache
from .components.secrets import Secret
from .config import VaultConfig
from .errors import (
    AuthenticationError,
    ConfigurationError,
    InvalidReferenceError,
    PermissionDeniedError,
    SecretNotFoundError,
    VaultKitError,
    VaultUnavailableError,
)
from .framework import SecretAccessFramework
from .providers import GatewayProvider, OpenBaoProvider, SecretProvider, VaultProvider, get_provider, registry
from .reference import SecretRef

__version__ = "1.0.0"

__all__ = [
    "SecretAccessFramework", "VaultConfig", "SecretRef", "Secret", "SecretProvider",
    "VaultProvider", "OpenBaoProvider", "GatewayProvider", "get_provider", "registry",
    "ISecretCache", "IAuditSink", "AuditEvent",
    "VaultKitError", "ConfigurationError", "InvalidReferenceError", "AuthenticationError",
    "PermissionDeniedError", "SecretNotFoundError", "VaultUnavailableError",
]
