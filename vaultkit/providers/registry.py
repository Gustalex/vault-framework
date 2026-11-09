"""Factory + registry de providers (padrão **Factory/Registry**)."""

from __future__ import annotations

from typing import Callable

from ..config import VaultConfig
from ..errors import ConfigurationError
from .base import SecretProvider

ProviderFactory = Callable[[VaultConfig], SecretProvider]


class ProviderRegistry:
    """Mapa ``nome -> factory``. Novos cofres entram com :meth:`register`,
    sem alterar o framework (princípio aberto/fechado)."""

    def __init__(self) -> None:
        self._factories: dict[str, ProviderFactory] = {}

    def register(self, name: str, factory: ProviderFactory | None = None):
        """Registra uma factory. Pode ser usado como decorator::

            @registry.register("meu-cofre")
            class MeuProvider(SecretProvider): ...
        """
        def deco(f: ProviderFactory) -> ProviderFactory:
            self._factories[name.lower()] = f
            return f
        return deco(factory) if factory is not None else deco

    def create(self, config: VaultConfig) -> SecretProvider:
        """Instancia o provider indicado por ``config.provider``."""
        try:
            factory = self._factories[config.provider.lower()]
        except KeyError:
            raise ConfigurationError(
                f"provider {config.provider!r} não registrado; disponíveis: {', '.join(self.names())}"
            ) from None
        return factory(config)

    def names(self) -> list[str]:
        return sorted(self._factories)


#: Registro global usado por :func:`get_provider`.
registry = ProviderRegistry()


def get_provider(config: VaultConfig | None = None) -> SecretProvider:
    """Atalho: cria o provider a partir da configuração (ou de ``VAULTKIT_*``)."""
    return registry.create(config or VaultConfig.from_env())
