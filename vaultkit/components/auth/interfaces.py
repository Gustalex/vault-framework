"""Interfaces providas pelo componente de autenticação."""

from __future__ import annotations

import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass
class AuthToken:
    """Token de acesso ao cofre. O valor nunca aparece no ``repr``."""

    value: str = field(repr=False)
    policies: list[str] = field(default_factory=list)
    ttl: int = 0  # segundos; 0 = sem expiração (token root/dev)
    renewable: bool = False
    accessor: str | None = field(default=None, repr=False)
    obtained_at: float = field(default_factory=time.monotonic)

    def expires_in(self, now: float | None = None) -> float:
        """Segundos restantes; ``inf`` quando o token não expira."""
        if not self.ttl:
            return float("inf")
        return self.ttl - ((now or time.monotonic()) - self.obtained_at)

    def is_expiring(self, skew: float = 0.2, now: float | None = None) -> bool:
        """Verdadeiro quando restam menos de ``skew`` (fração) do TTL."""
        if not self.ttl:
            return False
        return self.expires_in(now) <= self.ttl * skew


class IAuthenticator(ABC):
    """Contrato de um método de login no cofre (AppRole, token, ...)."""

    method: str = "abstract"

    @abstractmethod
    def login(self) -> AuthToken:
        """Autentica e devolve um novo token."""

    @abstractmethod
    def renew(self, token: AuthToken) -> AuthToken:
        """Renova o token (ou faz novo login se não for renovável)."""

    @abstractmethod
    def revoke(self, token: AuthToken) -> None:
        """Revoga o token no cofre."""

    @abstractmethod
    def lookup(self, token: AuthToken) -> dict:
        """Metadados do token (policies, ttl, ...), sem o valor."""


class ITokenProvider(ABC):
    """Fornece um token válido para quem precisa chamar o cofre."""

    @abstractmethod
    def get_token(self) -> str:
        """Token pronto para uso (faz login/renovação se preciso)."""

    def invalidate(self) -> None:  # pragma: no cover - padrão sem efeito
        """Descarta o token atual (força novo login na próxima chamada)."""
