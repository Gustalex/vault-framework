"""Interface provida pelo componente de cache."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class ISecretCache(ABC):
    """Cache em memória de segredos já lidos (nunca persiste em disco)."""

    @abstractmethod
    def get(self, key: str) -> Any | None:
        """Valor em cache ou ``None`` se ausente/expirado."""

    @abstractmethod
    def put(self, key: str, value: Any, ttl: float | None = None) -> None:
        """Guarda ``value`` por ``ttl`` segundos (padrão do cache se ``None``)."""

    @abstractmethod
    def invalidate(self, key: str | None = None) -> None:
        """Remove uma chave, ou tudo quando ``key`` é ``None``."""

    @abstractmethod
    def stats(self) -> dict[str, int]:
        """Contadores ``hits``, ``misses`` e ``size``."""
