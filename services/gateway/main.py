"""**api-gateway** (porta 8800) — ponto único de entrada da arquitetura.

Responsabilidades:

* **roteamento** de ``/api/<prefixo>/...`` para o microserviço dono do recurso;
* **service registry** estático com descoberta de saúde (``GET /api/services``);
* repasse apenas dos headers permitidos (``X-Vault-Token``, ``X-Client-Name``)
  e geração de ``X-Request-Id`` para correlacionar a auditoria;
* headers de resposta ``X-Served-By`` (microserviço:porta) e ``X-Gateway-Time-Ms``;
* serve o painel web em ``/`` (interface principal do sistema).

Tabela de rotas:

====================  ================  ==========================
Prefixo do gateway    Microserviço      Rota interna
====================  ================  ==========================
/api/auth/*           auth-service      /*
/api/secrets/*        secret-service    /secrets/*
/api/list/*           secret-service    /list/*
/api/cache/*          secret-service    /cache/*
/api/audit/*          audit-service     /*
====================  ================  ==========================

Banco de dados: nenhum.
"""

from __future__ import annotations

import asyncio
import json
import os
import time
import uuid
from contextlib import asynccontextmanager
from pathlib import Path
from typing import Any

import httpx
from fastapi import FastAPI, Request, Response
from fastapi.responses import FileResponse, JSONResponse

VERSION = "1.0.0"
NAME, PORT = "api-gateway", 8800

#: Registro de serviços: nome -> URL interna. Sobrescrevível por ``SERVICES`` (JSON).
DEFAULT_SERVICES = {
    "auth-service": os.environ.get("AUTH_URL", "http://127.0.0.1:8801"),
    "secret-service": os.environ.get("SECRET_URL", "http://127.0.0.1:8802"),
    "audit-service": os.environ.get("AUDIT_URL", "http://127.0.0.1:8803"),
}
SERVICES: dict[str, str] = json.loads(os.environ["SERVICES"]) if os.environ.get("SERVICES") else DEFAULT_SERVICES

#: prefixo público -> (serviço, prefixo interno)
ROUTES: dict[str, tuple[str, str]] = {
    "auth": ("auth-service", ""),
    "secrets": ("secret-service", "/secrets"),
    "list": ("secret-service", "/list"),
    "cache": ("secret-service", "/cache"),
    "audit": ("audit-service", ""),
}

FORWARD_HEADERS = ("x-vault-token", "x-client-name", "content-type")
STATIC = Path(__file__).parent / "static"

client = httpx.AsyncClient(timeout=float(os.environ.get("GATEWAY_TIMEOUT", "15")))


@asynccontextmanager
async def lifespan(_: FastAPI):
    yield
    await client.aclose()


app = FastAPI(title=NAME, version=VERSION, lifespan=lifespan,
              description="API Gateway do VaultKit: roteia para auth-service, secret-service e audit-service")
started_at = time.time()


def _port(url: str) -> int | None:
    return httpx.URL(url).port


@app.get("/", include_in_schema=False)
def dashboard() -> FileResponse:
    """Painel web (interface principal)."""
    return FileResponse(STATIC / "index.html")


@app.get("/health", tags=["infra"], summary="Estado do gateway")
def health() -> dict:
    return {"service": NAME, "status": "up", "port": PORT, "version": VERSION,
            "uptime_s": round(time.time() - started_at, 1), "description": "API Gateway"}


@app.get("/api/routes", tags=["infra"], summary="Tabela de roteamento")
def routes() -> dict:
    return {"routes": [{"prefix": f"/api/{p}/*", "service": s, "target": f"{SERVICES[s]}{inner}/*"}
                       for p, (s, inner) in ROUTES.items()]}


async def _probe(name: str, url: str) -> dict[str, Any]:
    t0 = time.perf_counter()
    try:
        r = await client.get(f"{url}/health", timeout=3)
        info = r.json()
        status = info.get("status", "up") if r.status_code == 200 else "down"
    except (httpx.HTTPError, ValueError):
        info, status = {}, "down"
    return {"name": name, "url": url, "port": info.get("port") or _port(url), "status": status,
            "latency_ms": round((time.perf_counter() - t0) * 1000, 1), "version": info.get("version"),
            "description": info.get("description"), "uptime_s": info.get("uptime_s"),
            "dependencies": info.get("dependencies")}


@app.get("/api/services", tags=["infra"], summary="Microserviços registrados e seu estado")
async def services() -> dict:
    """Service registry + health check concorrente de cada microserviço."""
    probes = await asyncio.gather(*(_probe(n, u) for n, u in SERVICES.items()))
    gw = {**health(), "name": NAME, "url": f"http://api-gateway:{PORT}", "latency_ms": 0.0, "status": "up"}
    return {"services": [gw, *probes]}


@app.api_route("/api/{prefix}/{rest:path}", methods=["GET", "POST", "PUT", "DELETE"], tags=["proxy"],
               summary="Roteia para o microserviço responsável")
async def proxy(prefix: str, rest: str, request: Request) -> Response:
    """Encaminha a requisição e devolve a resposta do microserviço sem alterá-la."""
    if prefix not in ROUTES:
        return JSONResponse({"detail": f"rota /api/{prefix} desconhecida"}, status_code=404)
    service, inner = ROUTES[prefix]
    base = SERVICES[service]
    url = f"{base}{inner}/{rest}" if rest else f"{base}{inner}"
    headers = {k: v for k, v in request.headers.items() if k.lower() in FORWARD_HEADERS}
    request_id = request.headers.get("x-request-id") or uuid.uuid4().hex[:12]
    headers["x-request-id"] = request_id
    t0 = time.perf_counter()
    try:
        upstream = await client.request(request.method, url, params=request.query_params,
                                        content=await request.body(), headers=headers)
    except httpx.HTTPError:
        return JSONResponse({"detail": f"{service} indisponível", "error": "VaultUnavailableError"},
                            status_code=503, headers={"X-Served-By": f"{service}:{_port(base)}"})
    elapsed = round((time.perf_counter() - t0) * 1000, 1)
    out_headers = {"X-Served-By": f"{service}:{_port(base)}", "X-Gateway-Time-Ms": str(elapsed),
                   "X-Request-Id": request_id}
    return Response(content=upstream.content, status_code=upstream.status_code,
                    media_type=upstream.headers.get("content-type"), headers=out_headers)

