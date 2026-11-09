"""Infraestrutura comum aos microserviços: configuração, transporte, erros e health."""

from __future__ import annotations

import logging
import os
import time
from typing import Any, Callable

from fastapi import FastAPI, Request
from fastapi.responses import JSONResponse

from vaultkit.components.audit import AuditEvent, HttpAuditSink, IAuditSink, LoggingAuditSink
from vaultkit.config import VaultConfig, _bool
from vaultkit.errors import VaultKitError
from vaultkit.http import VaultHttpClient

logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"), format="%(asctime)s %(name)s %(message)s")

VERSION = "1.0.0"


def bao_config() -> VaultConfig:
    """Configuração do cofre lida de ``BAO_*`` (endereço, namespace, TLS)."""
    return VaultConfig(
        address=os.environ.get("BAO_ADDR", "http://127.0.0.1:8210").rstrip("/"),
        namespace=os.environ.get("BAO_NAMESPACE", "vaultkit") or None,
        allow_http=_bool(os.environ.get("BAO_ALLOW_HTTP"), True),
        verify_tls=os.environ.get("BAO_CA_CERT") or True,
        timeout=float(os.environ.get("BAO_TIMEOUT", "10")),
        client_name=os.environ.get("SERVICE_NAME", "service"),
    )


def make_transport() -> VaultHttpClient:
    """Transporte HTTP do framework (interface requerida ``IVaultTransport``)."""
    return VaultHttpClient(bao_config())


def make_audit_sink(service: str) -> IAuditSink:
    """Eventos vão para o *audit-service*; sem ``AUDIT_URL``, para o log."""
    url = os.environ.get("AUDIT_URL")
    return HttpAuditSink(url) if url else LoggingAuditSink()


def install_error_handler(app: FastAPI) -> None:
    """Converte :class:`VaultKitError` em JSON com o status HTTP correspondente."""

    @app.exception_handler(VaultKitError)
    async def _handler(_: Request, exc: VaultKitError) -> JSONResponse:
        return JSONResponse(status_code=exc.status_code,
                            content={"detail": str(exc), "error": type(exc).__name__})


def create_service(name: str, port: int, description: str,
                   health_check: Callable[[], dict[str, Any]] | None = None) -> FastAPI:
    """Cria a aplicação FastAPI com ``/health`` e tratamento de erros padronizados."""
    app = FastAPI(title=name, version=VERSION, description=description)
    install_error_handler(app)
    started = time.time()

    @app.get("/health", tags=["infra"], summary="Estado do microserviço")
    def health() -> dict[str, Any]:
        info: dict[str, Any] = {"service": name, "status": "up", "port": port, "version": VERSION,
                                "uptime_s": round(time.time() - started, 1), "description": description}
        if health_check:
            try:
                info["dependencies"] = health_check()
            except VaultKitError as exc:
                info["status"] = "degraded"
                info["dependencies"] = {"error": str(exc)}
        return info

    return app


def actor_of(request: Request) -> str:
    """Quem chamou (header ``X-Client-Name`` repassado pelo gateway)."""
    return request.headers.get("x-client-name", "anonymous")


def audit(sink: IAuditSink, service: str, request: Request, action: str, resource: str,
          outcome: str, started: float, **detail: Any) -> None:
    sink.record(AuditEvent(action=action, resource=resource, outcome=outcome, actor=actor_of(request),
                           service=service, latency_ms=round((time.perf_counter() - started) * 1000, 2),
                           detail={"request_id": request.headers.get("x-request-id"), **detail}))
