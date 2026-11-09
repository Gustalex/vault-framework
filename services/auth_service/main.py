"""**auth-service** (porta 8801) — autenticação no cofre.

Reutiliza o **componente de Autenticação** do framework
(:class:`~vaultkit.components.auth.AppRoleAuthenticator` e
:class:`~vaultkit.components.auth.StaticTokenAuthenticator`).

Endpoints:

=======  ==========  ================================================
Método   Rota        Descrição
=======  ==========  ================================================
POST     /login      AppRole (role_id + secret_id) → token do cofre
POST     /renew      renova o token do header ``X-Vault-Token``
POST     /revoke     revoga o token do header ``X-Vault-Token``
GET      /lookup     policies/TTL do token (sem o valor)
GET      /health     estado do serviço e do cofre
=======  ==========  ================================================

Banco de dados: nenhum (o estado de sessão fica no próprio OpenBao).
"""

from __future__ import annotations

import time

from fastapi import Header, Request, Response
from pydantic import BaseModel, Field

from vaultkit.components.auth import AppRoleAuthenticator, AuthToken, StaticTokenAuthenticator, token_from_auth
from vaultkit.errors import VaultKitError

from ..common import audit, create_service, make_audit_sink, make_transport

NAME, PORT = "auth-service", 8801
transport = make_transport()
sink = make_audit_sink(NAME)


def _vault_health() -> dict:
    body = transport.request("GET", "sys/health", use_namespace=False)
    return {"openbao": {"version": body.get("version"), "sealed": body.get("sealed"),
                        "namespace": transport.config.namespace}}


app = create_service(NAME, PORT, "Autenticação AppRole no OpenBao (componente auth)", _vault_health)


class LoginRequest(BaseModel):
    role_id: str = Field(..., description="RoleID do AppRole")
    secret_id: str = Field(..., description="SecretID do AppRole")
    mount: str = Field("approle", description="Caminho do método AppRole")


def _auth_payload(token: AuthToken) -> dict:
    return {"auth": {"client_token": token.value, "token_policies": token.policies,
                     "lease_duration": token.ttl, "renewable": token.renewable}}


@app.post("/login", tags=["auth"], summary="Login AppRole")
def login(body: LoginRequest, request: Request) -> dict:
    started = time.perf_counter()
    try:
        token = AppRoleAuthenticator(transport, body.role_id, body.secret_id, body.mount).login()
    except VaultKitError as exc:
        audit(sink, NAME, request, "auth.login", f"approle:{body.mount}", "denied", started,
              error=type(exc).__name__)
        raise
    audit(sink, NAME, request, "auth.login", f"approle:{body.mount}", "success", started,
          policies=token.policies, ttl=token.ttl)
    return _auth_payload(token)


@app.post("/renew", tags=["auth"], summary="Renova o token")
def renew(request: Request, x_vault_token: str = Header(...)) -> dict:
    started = time.perf_counter()
    body = transport.request("POST", "auth/token/renew-self", token=x_vault_token, json_body={})
    token = token_from_auth(body.get("auth"))
    audit(sink, NAME, request, "auth.renew", "token:self", "success", started, ttl=token.ttl)
    return _auth_payload(token)


@app.post("/revoke", tags=["auth"], summary="Revoga o token", status_code=204)
def revoke(request: Request, x_vault_token: str = Header(...)) -> Response:
    started = time.perf_counter()
    StaticTokenAuthenticator(transport, x_vault_token).revoke(AuthToken(value=x_vault_token))
    audit(sink, NAME, request, "auth.revoke", "token:self", "success", started)
    return Response(status_code=204)


@app.get("/lookup", tags=["auth"], summary="Metadados do token")
def lookup(x_vault_token: str = Header(...)) -> dict:
    return StaticTokenAuthenticator(transport, x_vault_token).lookup(AuthToken(value=x_vault_token))
