"""Contrato comum dos providers de segredo (padrão **Strategy**)."""

from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Iterable

from ..components.secrets import Secret
from ..reference import SecretRef


class SecretProvider(ABC):
    """Estratégia de acesso a um cofre.

    A aplicação (e o framework) só conhecem este contrato; cada cofre ganha um
    **Adapter** que traduz ``get_secret`` para a API dele. Trocar de cofre é
    trocar a estratégia escolhida pela factory, sem reescrever a aplicação.
    """

    name: str = "abstract"

    @abstractmethod
    def get_secret(self, ref: SecretRef) -> Secret:
        """Lê o segredo apontado por ``ref``."""

    def get_many(self, refs: Iterable[SecretRef]) -> list[Secret]:
        """Lê vários segredos (implementação padrão: um por vez)."""
        return [self.get_secret(r) for r in refs]

    def put_secret(self, ref: SecretRef, data: dict) -> int:  # pragma: no cover - opcional
        """Grava um segredo (nem todo provider permite escrita)."""
        raise NotImplementedError(f"{self.name} não suporta escrita")

    def health(self) -> dict:
        """Estado do cofre/gateway, sem autenticar."""
        return {"provider": self.name, "status": "unknown"}

    def close(self) -> None:
        """Libera recursos (revoga token, fecha conexões)."""

    def __enter__(self) -> "SecretProvider":
        return self

    def __exit__(self, *exc) -> None:
        self.close()
