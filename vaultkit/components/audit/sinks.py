"""Implementações de :class:`IAuditSink`."""

from __future__ import annotations

import json
import logging
import sqlite3
import threading
from collections import deque
from typing import Any, Iterable

import httpx

from .interfaces import AuditEvent, IAuditSink

log = logging.getLogger("vaultkit.audit")


class LoggingAuditSink(IAuditSink):
    """Escreve cada evento como uma linha JSON no ``logging``."""

    def __init__(self, logger: logging.Logger | None = None, level: int = logging.INFO):
        self._log = logger or log
        self._level = level

    def record(self, event: AuditEvent) -> None:
        self._log.log(self._level, "audit %s", json.dumps(event.to_dict(), ensure_ascii=False))


class MemoryAuditSink(IAuditSink):
    """Guarda os últimos ``maxlen`` eventos em memória (testes e dashboards)."""

    def __init__(self, maxlen: int = 500):
        self.events: deque[AuditEvent] = deque(maxlen=maxlen)

    def record(self, event: AuditEvent) -> None:
        self.events.append(event)

    def query(self, limit: int = 50) -> list[dict[str, Any]]:
        return [e.to_dict() for e in list(self.events)[::-1][:limit]]


class SQLiteAuditSink(IAuditSink):
    """Persiste eventos em SQLite — banco de dados do *audit-service*."""

    def __init__(self, path: str = ":memory:"):
        self._conn = sqlite3.connect(path, check_same_thread=False)
        self._lock = threading.Lock()
        with self._lock:
            self._conn.execute(
                """CREATE TABLE IF NOT EXISTS audit_events (
                       id INTEGER PRIMARY KEY AUTOINCREMENT,
                       timestamp TEXT NOT NULL, service TEXT NOT NULL, actor TEXT NOT NULL,
                       action TEXT NOT NULL, resource TEXT NOT NULL, outcome TEXT NOT NULL,
                       latency_ms REAL, detail TEXT NOT NULL)"""
            )
            self._conn.commit()

    def record(self, event: AuditEvent) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT INTO audit_events (timestamp, service, actor, action, resource, outcome, latency_ms, detail)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                (event.timestamp, event.service, event.actor, event.action, event.resource,
                 event.outcome, event.latency_ms, json.dumps(event.detail, ensure_ascii=False)),
            )
            self._conn.commit()

    def query(self, limit: int = 50, service: str | None = None) -> list[dict[str, Any]]:
        sql = "SELECT id, timestamp, service, actor, action, resource, outcome, latency_ms, detail FROM audit_events"
        args: list[Any] = []
        if service:
            sql += " WHERE service = ?"
            args.append(service)
        sql += " ORDER BY id DESC LIMIT ?"
        args.append(limit)
        with self._lock:
            rows = self._conn.execute(sql, args).fetchall()
        cols = ["id", "timestamp", "service", "actor", "action", "resource", "outcome", "latency_ms", "detail"]
        return [{**dict(zip(cols, r)), "detail": json.loads(r[-1])} for r in rows]

    def stats(self) -> dict[str, Any]:
        with self._lock:
            total = self._conn.execute("SELECT COUNT(*) FROM audit_events").fetchone()[0]
            by_outcome = dict(self._conn.execute(
                "SELECT outcome, COUNT(*) FROM audit_events GROUP BY outcome").fetchall())
            by_action = dict(self._conn.execute(
                "SELECT action, COUNT(*) FROM audit_events GROUP BY action").fetchall())
        return {"total": total, "by_outcome": by_outcome, "by_action": by_action}


class HttpAuditSink(IAuditSink):
    """Envia eventos ao *audit-service* (``POST /events``). Erros são só logados."""

    def __init__(self, url: str, timeout: float = 2.0, transport: httpx.BaseTransport | None = None):
        self._client = httpx.Client(base_url=url.rstrip("/"), timeout=timeout, transport=transport)

    def record(self, event: AuditEvent) -> None:
        try:
            self._client.post("/events", json=event.to_dict())
        except httpx.HTTPError as exc:  # auditoria nunca derruba a operação
            log.warning("audit-service indisponível: %s", exc.__class__.__name__)


class CompositeAuditSink(IAuditSink):
    """Encaminha o evento para vários destinos (padrão Composite)."""

    def __init__(self, sinks: Iterable[IAuditSink]):
        self.sinks = list(sinks)

    def record(self, event: AuditEvent) -> None:
        for sink in self.sinks:
            try:
                sink.record(event)
            except Exception:  # noqa: BLE001 - um destino com falha não afeta os outros
                log.exception("falha no destino de auditoria %s", type(sink).__name__)

    def query(self, limit: int = 50) -> list[dict[str, Any]]:
        for sink in self.sinks:
            rows = sink.query(limit)
            if rows:
                return rows
        return []
