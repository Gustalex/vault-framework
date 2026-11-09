"""Adapter que acessa o cofre através da arquitetura de microserviços (API Gateway)."""

from __future__ import annotations

import httpx

from ..components.auth import AuthToken, IAuthenticator, TokenManager, token_from_auth
from ..components.secrets import Secret
from ..config import VaultConfig
from ..errors import PermissionDeniedError
from ..http import VaultHttpClient
from ..reference import SecretRef
from .base import SecretProvider


class GatewayAuthenticator(IAuthenticator):
    """Login pelo *auth-service* via gateway (``POST /api/auth/login``)."""

    method = "approle-gateway"

    def __init__(self, client: VaultHttpClient, config: VaultConfig):
        self._client = client
        self._config = config

    def login(self) -> AuthToken:
        body = self._client.request("POST", "/api/auth/login", json_body={
            "role_id": self._config.role_id, "secret_id": self._config.secret_id,
        })
        return token_from_auth(body.get("auth"))

    def renew(self, token: AuthToken) -> AuthToken:
        if not token.renewable:
            return self.login()
        body = self._client.request("POST", "/api/auth/renew", token=token.value, json_body={})
        return token_from_auth(body.get("auth"))

    def revoke(self, token: AuthToken) -> None:
        self._client.request("POST", "/api/auth/revoke", token=token.value, json_body={})

    def lookup(self, token: AuthToken) -> dict:
        return self._client.request("GET", "/api/auth/lookup", token=token.value)


class GatewayProvider(SecretProvider):
    """**Adapter** cujo "cofre" é o API Gateway (porta 8800).

    A aplicação usa o mesmo contrato ``get_secret``; por baixo, a chamada passa
    pelo gateway, que roteia para o *auth-service* (login) e para o
    *secret-service* (leitura) e registra tudo no *audit-service*.
    """

    name = "gateway"

    def __init__(self, config: VaultConfig, http_transport: httpx.BaseTransport | None = None):
        self.config = config.validate()
        self.client = VaultHttpClient(config.with_overrides(namespace=None), transport=http_transport,
                                      base_url=config.gateway_url)
        self.client._client.headers["X-Client-Name"] = config.client_name
        self.auth = TokenManager(GatewayAuthenticator(self.client, config))

    def _read(self, ref: SecretRef) -> Secret:
        mount = ref.mount or self.config.kv_mount
        params = {"version": ref.version} if ref.version else None
        body = self.client.request("GET", f"/api/secrets/{mount}/{ref.path}",
                                   token=self.auth.get_token(), params=params)
        return Secret(path=body["path"], data=dict(body["data"]), version=body.get("version"),
                      created_time=body.get("created_time"), mount=mount,
                      custom_metadata=body.get("custom_metadata"))

    def get_secret(self, ref: SecretRef) -> Secret:
        try:
            return self._read(ref)
        except PermissionDeniedError:
            if self.auth.is_valid():
                raise
            self.auth.invalidate()
            return self._read(ref)

    def put_secret(self, ref: SecretRef, data: dict) -> int:
        mount = ref.mount or self.config.kv_mount
        body = self.client.request("PUT", f"/api/secrets/{mount}/{ref.path}",
                                   token=self.auth.get_token(), json_body={"data": data})
        return int(body.get("version") or 0)

    def health(self) -> dict:
        body = self.client.request("GET", "/api/services")
        up = [s for s in body.get("services", []) if s.get("status") == "up"]
        return {"provider": self.name, "status": "ok" if len(up) == len(body.get("services", [])) else "degraded",
                "services": {s["name"]: s.get("status") for s in body.get("services", [])}}

    def close(self) -> None:
        try:
            self.auth.revoke()
        except Exception:  # noqa: BLE001
            pass
        self.client.close()
