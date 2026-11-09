"""**secret-service** (porta 8802) — leitura e escrita de segredos.

Reutiliza os componentes **Segredos** (:class:`~vaultkit.components.secrets.KVv2SecretStore`)
e **Cache** (:class:`~vaultkit.components.cache.TTLSecretCache`) do framework.
O token do cliente chega em ``X-Vault-Token`` e é entregue ao componente por um
:class:`~vaultkit.components.auth.StaticTokenProvider`: quem decide o que pode ser
lido é a policy do próprio OpenBao (menor privilégio).

=======  ===========================  ====================================
Método   Rota                         Descrição
=======  ===========================  ====================================
GET      /secrets/{mount}/{path}      lê (``?version=N`` opcional)
PUT      /secrets/{mount}/{path}      grava nova versão
GET      /list/{mount}/{path}         lista chaves
GET      /cache/stats                 acertos/erros do cache
GET      /health                      estado do serviço e do cofre
=======  ===========================  ====================================

Banco de dados: OpenBao (KV v2) + cache em memória.
"""

from __future__ import annotations

import hashlib
import os
import time
from typing import Any

from fastapi import Header, Query, Request
from pydantic import BaseModel

from vaultkit.components.auth import StaticTokenProvider
from vaultkit.components.cache import TTLSecretCache
from vaultkit.components.secrets import KVv2SecretStore, Secret
from vaultkit.errors import PermissionDeniedError, VaultKitError

from ..common import audit, create_service, make_audit_sink, make_transport

NAME, PORT = "secret-service", 8802
transport = make_transport()
sink = make_audit_sink(NAME)
cache = TTLSecretCache(ttl=float(os.environ.get("SECRET_CACHE_TTL", "15")))


def _vault_health() -> dict:
    body = transport.request("GET", "sys/health", use_namespace=False)
    return {"openbao": {"version": body.get("version"), "sealed": body.get("sealed")},
            "cache": cache.stats()}


app = create_service(NAME, PORT, "Leitura/escrita no KV v2 com cache (componentes secrets + cache)",
                     _vault_health)


def _store(token: str, mount: str) -> KVv2SecretStore:
    return KVv2SecretStore(transport, StaticTokenProvider(token), mount)


def _cache_key(token: str, mount: str, path: str, version: int | None) -> str:
    # o cache é separado por token: um cliente nunca recebe o que outro leu
    tk = hashlib.sha256(token.encode()).hexdigest()[:16]
    return f"{tk}|{mount}:{path}@{version or 'latest'}"


def _to_json(s: Secret, cached: bool) -> dict[str, Any]:
    return {"path": s.path, "mount": s.mount, "data": s.data, "version": s.version,
            "created_time": s.created_time, "custom_metadata": s.custom_metadata, "cached": cached}


@app.get("/secrets/{mount}/{path:path}", tags=["secrets"], summary="Lê um segredo")
def read_secret(mount: str, path: str, request: Request, version: int | None = Query(None),
                x_vault_token: str = Header(...)) -> dict:
    started = time.perf_counter()
    key = _cache_key(x_vault_token, mount, path, version)
    hit = cache.get(key)
    if hit is not None:
        audit(sink, NAME, request, "secret.read", f"{mount}:{path}", "cache_hit", started, version=hit.version)
        return _to_json(hit, cached=True)
    try:
        secret = _store(x_vault_token, mount).read(path, version)
    except PermissionDeniedError:
        audit(sink, NAME, request, "secret.read", f"{mount}:{path}", "denied", started)
        raise
    except VaultKitError as exc:
        audit(sink, NAME, request, "secret.read", f"{mount}:{path}", "error", started, error=type(exc).__name__)
        raise
    cache.put(key, secret)
    audit(sink, NAME, request, "secret.read", f"{mount}:{path}", "success", started,
          version=secret.version, keys=secret.keys())
    return _to_json(secret, cached=False)


class WriteRequest(BaseModel):
    data: dict[str, Any]


@app.put("/secrets/{mount}/{path:path}", tags=["secrets"], summary="Grava nova versão")
def write_secret(mount: str, path: str, body: WriteRequest, request: Request,
                 x_vault_token: str = Header(...)) -> dict:
    started = time.perf_counter()
    try:
        version = _store(x_vault_token, mount).write(path, body.data)
    except VaultKitError as exc:
        audit(sink, NAME, request, "secret.write", f"{mount}:{path}",
              "denied" if isinstance(exc, PermissionDeniedError) else "error", started)
        raise
    cache.invalidate()  # nova versão: descarta leituras antigas
    audit(sink, NAME, request, "secret.write", f"{mount}:{path}", "success", started,
          version=version, keys=list(body.data))
    return {"path": path, "mount": mount, "version": version}


@app.get("/list/{mount}", tags=["secrets"], summary="Lista a raiz do mount")
@app.get("/list/{mount}/{path:path}", tags=["secrets"], summary="Lista chaves")
def list_secrets(mount: str, request: Request, path: str = "", x_vault_token: str = Header(...)) -> dict:
    started = time.perf_counter()
    keys = _store(x_vault_token, mount).list(path)
    audit(sink, NAME, request, "secret.list", f"{mount}:{path or '/'}", "success", started, count=len(keys))
    return {"mount": mount, "path": path, "keys": keys}


@app.get("/cache/stats", tags=["infra"], summary="Estatísticas do cache")
def cache_stats() -> dict:
    return cache.stats()
