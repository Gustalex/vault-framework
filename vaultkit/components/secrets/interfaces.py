"""Interface provida pelo componente de segredos."""

from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

from ...errors import SecretNotFoundError


@dataclass(frozen=True)
class Secret:
    """Segredo lido do cofre. Os valores nunca aparecem no ``repr``/``str``."""

    path: str
    data: dict[str, Any] = field(repr=False)
    version: int | None = None
    created_time: str | None = None
    mount: str | None = None
    custom_metadata: dict[str, Any] | None = None

    def value(self, key: str | None = None) -> Any:
        """Valor de uma chave; sem ``key``, o único valor (ou o dicionário inteiro).

        :raises SecretNotFoundError: a chave não existe no segredo.
        """
        if key is None:
            return next(iter(self.data.values())) if len(self.data) == 1 else dict(self.data)
        if key not in self.data:
            raise SecretNotFoundError(f"chave {key!r} não existe em {self.path}")
        return self.data[key]

    def keys(self) -> list[str]:
        return list(self.data)

    def describe(self) -> dict[str, Any]:
        """Metadados seguros para log/auditoria (só nomes das chaves)."""
        return {"path": self.path, "mount": self.mount, "version": self.version, "keys": self.keys()}


class ISecretStore(ABC):
    """Contrato de um armazenamento de segredos (KV v2 no OpenBao/Vault)."""

    @abstractmethod
    def read(self, path: str, version: int | None = None) -> Secret:
        """Lê um segredo (última versão por padrão)."""

    @abstractmethod
    def write(self, path: str, data: dict[str, Any]) -> int:
        """Grava nova versão e devolve o número dela."""

    @abstractmethod
    def list(self, path: str = "") -> list[str]:
        """Lista chaves sob ``path`` (pastas terminam com ``/``)."""

    @abstractmethod
    def delete(self, path: str) -> None:
        """Remove (soft-delete) a última versão."""
