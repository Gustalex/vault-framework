"""Providers (Strategy + Adapter) e a factory que os escolhe (Factory/Registry)."""

from .base import SecretProvider
from .gateway import GatewayProvider
from .registry import ProviderRegistry, get_provider, registry
from .vault import OpenBaoProvider, VaultProvider

registry.register("vault", VaultProvider)
registry.register("openbao", OpenBaoProvider)
registry.register("gateway", GatewayProvider)

__all__ = [
    "SecretProvider", "VaultProvider", "OpenBaoProvider", "GatewayProvider",
    "ProviderRegistry", "registry", "get_provider",
]
