"""Implementação do KV v2 (OpenBao e HashiCorp Vault expõem a mesma API)."""

from __future__ import annotations

from typing import Any

from ...errors import SecretNotFoundError
from ...http import IVaultTransport
from ..auth.interfaces import ITokenProvider
from .interfaces import ISecretStore, Secret


class KVv2SecretStore(ISecretStore):
    """Armazenamento KV versão 2.

    ``GET  /v1/<mount>/data/<path>?version=N``  → leitura
    ``POST /v1/<mount>/data/<path>``            → escrita
    ``LIST /v1/<mount>/metadata/<path>``        → listagem
    ``DELETE /v1/<mount>/data/<path>``          → remoção da última versão

    :param transport: interface requerida para HTTP.
    :param token_provider: interface requerida que entrega o token (componente auth).
    :param mount: caminho onde o KV v2 está montado (padrão ``secret``).
    """

    def __init__(self, transport: IVaultTransport, token_provider: ITokenProvider, mount: str = "secret"):
        self._transport = transport
        self._tokens = token_provider
        self.mount = mount.strip("/")

    def read(self, path: str, version: int | None = None) -> Secret:
        params = {"version": version} if version else None
        body = self._transport.request("GET", f"{self.mount}/data/{path.strip('/')}",
                                       token=self._tokens.get_token(), params=params)
        payload = body.get("data") or {}
        meta = payload.get("metadata") or {}
        if payload.get("data") is None:
            # versão apagada/destruída: o cofre devolve data=null
            raise SecretNotFoundError(f"segredo sem dados (apagado?): {path}")
        return Secret(
            path=path.strip("/"),
            data=dict(payload["data"]),
            version=meta.get("version"),
            created_time=meta.get("created_time"),
            mount=self.mount,
            custom_metadata=meta.get("custom_metadata"),
        )

    def write(self, path: str, data: dict[str, Any]) -> int:
        body = self._transport.request("POST", f"{self.mount}/data/{path.strip('/')}",
                                       token=self._tokens.get_token(), json_body={"data": data})
        return int((body.get("data") or {}).get("version") or 0)

    def list(self, path: str = "") -> list[str]:
        try:
            body = self._transport.request("LIST", f"{self.mount}/metadata/{path.strip('/')}",
                                           token=self._tokens.get_token())
        except SecretNotFoundError:
            return []
        return list((body.get("data") or {}).get("keys") or [])

    def delete(self, path: str) -> None:
        self._transport.request("DELETE", f"{self.mount}/data/{path.strip('/')}", token=self._tokens.get_token())
