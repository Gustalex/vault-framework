"""Interface provida pelo componente de auditoria."""

from __future__ import annotations

import datetime as dt
from abc import ABC, abstractmethod
from dataclasses import asdict, dataclass, field
from typing import Any

from ...masking import mask


def _now() -> str:
    return dt.datetime.now(dt.timezone.utc).isoformat(timespec="milliseconds")


@dataclass
class AuditEvent:
    """Registro de uma operação no cofre. ``detail`` é mascarado na criação."""

    action: str  # ex.: "secret.read", "auth.login"
    resource: str  # ex.: "secret:apps/db-checker/postgres"
    outcome: str = "success"  # "success" | "denied" | "error" | "cache_hit"
    actor: str = "anonymous"
    service: str = "vaultkit"
    latency_ms: float | None = None
    detail: dict[str, Any] = field(default_factory=dict)
    timestamp: str = field(default_factory=_now)

    def __post_init__(self) -> None:
        self.detail = mask(self.detail or {})

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class IAuditSink(ABC):
    """Destino de eventos de auditoria."""

    @abstractmethod
    def record(self, event: AuditEvent) -> None:
        """Registra o evento. Falha de auditoria nunca derruba a operação."""

    def query(self, limit: int = 50) -> list[dict[str, Any]]:
        """Eventos mais recentes primeiro (opcional; nem todo destino consulta)."""
        return []
