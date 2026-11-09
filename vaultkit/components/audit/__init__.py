"""Componente de Auditoria.

Interface provida: :class:`IAuditSink`. Sem interfaces requeridas externas.
"""

from .interfaces import AuditEvent, IAuditSink
from .sinks import CompositeAuditSink, HttpAuditSink, LoggingAuditSink, MemoryAuditSink, SQLiteAuditSink

__all__ = [
    "AuditEvent", "IAuditSink", "LoggingAuditSink", "MemoryAuditSink",
    "SQLiteAuditSink", "HttpAuditSink", "CompositeAuditSink",
]
