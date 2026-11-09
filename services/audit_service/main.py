"""**audit-service** (porta 8803) — trilha de auditoria.

Reutiliza o **componente de Auditoria** (:class:`~vaultkit.components.audit.SQLiteAuditSink`).
Recebe eventos já mascarados dos outros microserviços; nunca armazena token ou segredo.

=======  =========  ================================================
Método   Rota       Descrição
=======  =========  ================================================
POST     /events    registra um evento
GET      /events    últimos eventos (``?limit=50&service=...``)
GET      /stats     totais por resultado e por ação
GET      /health    estado do serviço
=======  =========  ================================================

Banco de dados: **SQLite** (``/data/audit.db`` no container).
"""

from __future__ import annotations

import os
from typing import Any

from fastapi import Query
from pydantic import BaseModel, Field

from vaultkit.components.audit import AuditEvent, SQLiteAuditSink

from ..common import create_service

NAME, PORT = "audit-service", 8803
DB_PATH = os.environ.get("AUDIT_DB", "data/audit.db")
if DB_PATH != ":memory:":
    os.makedirs(os.path.dirname(DB_PATH) or ".", exist_ok=True)
sink = SQLiteAuditSink(DB_PATH)

app = create_service(NAME, PORT, "Trilha de auditoria em SQLite (componente audit)",
                     lambda: {"sqlite": {"path": DB_PATH, "events": sink.stats()["total"]}})


class EventIn(BaseModel):
    action: str
    resource: str
    outcome: str = "success"
    actor: str = "anonymous"
    service: str = "unknown"
    latency_ms: float | None = None
    detail: dict[str, Any] = Field(default_factory=dict)
    timestamp: str | None = None


@app.post("/events", tags=["audit"], summary="Registra evento", status_code=201)
def record(evt: EventIn) -> dict:
    data = evt.model_dump(exclude_none=True)
    sink.record(AuditEvent(**data))  # AuditEvent mascara 'detail' de novo (defesa em profundidade)
    return {"status": "recorded"}


@app.get("/events", tags=["audit"], summary="Lista eventos")
def events(limit: int = Query(50, ge=1, le=500), service: str | None = None) -> dict:
    return {"events": sink.query(limit, service)}


@app.get("/stats", tags=["audit"], summary="Estatísticas")
def stats() -> dict:
    return sink.stats()
