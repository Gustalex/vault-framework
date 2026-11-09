"""Adapter para HashiCorp Vault e OpenBao (mesma API HTTP)."""

from __future__ import annotations

import httpx

from ..components.auth import TokenManager, create_authenticator
from ..components.secrets import KVv2SecretStore, Secret
from ..config import VaultConfig
from ..errors import PermissionDeniedError
from ..http import IVaultTransport, VaultHttpClient
from ..reference import SecretRef
from .base import SecretProvider


class VaultProvider(SecretProvider):
    """**Adapter** que monta os componentes *auth* + *secrets* sobre o transporte HTTP.

    Fluxo de ``get_secret``::

        TokenManager.get_token()  -> POST /v1/auth/approle/login   (1ª vez)
        KVv2SecretStore.read()    -> GET  /v1/<mount>/data/<path>

    Se o cofre responder 403, o adapter pergunta ao cofre se o token ainda vale
    (``lookup-self``). Token inválido (expirado/revogado) → **um** novo login e
    nova leitura. Token válido → é negação de policy e o erro sobe direto.
    """

    name = "vault"

    def __init__(self, config: VaultConfig, transport: IVaultTransport | None = None,
                 http_transport: httpx.BaseTransport | None = None):
        self.config = config.validate()
        self.transport: IVaultTransport = transport or VaultHttpClient(config, transport=http_transport)
        self.auth = TokenManager(create_authenticator(config, self.transport))
        self._stores: dict[str, KVv2SecretStore] = {}

    def store(self, mount: str | None = None) -> KVv2SecretStore:
        """Componente KV v2 do ``mount`` (criado sob demanda e reaproveitado)."""
        mount = (mount or self.config.kv_mount).strip("/")
        if mount not in self._stores:
            self._stores[mount] = KVv2SecretStore(self.transport, self.auth, mount)
        return self._stores[mount]

    def get_secret(self, ref: SecretRef) -> Secret:
        store = self.store(ref.mount)
        try:
            return store.read(ref.path, ref.version)
        except PermissionDeniedError:
            if self.config.auth_method != "approle" or self.auth.is_valid():
                raise
            self.auth.invalidate()
            return store.read(ref.path, ref.version)

    def put_secret(self, ref: SecretRef, data: dict) -> int:
        return self.store(ref.mount).write(ref.path, data)

    def list_secrets(self, path: str = "", mount: str | None = None) -> list[str]:
        return self.store(mount).list(path)

    def health(self) -> dict:
        body = self.transport.request("GET", "sys/health", use_namespace=False)
        return {
            "provider": self.name, "status": "sealed" if body.get("sealed") else "ok",
            "version": body.get("version"), "initialized": body.get("initialized"),
            "namespace": self.config.namespace,
        }

    def close(self) -> None:
        try:
            self.auth.revoke()
        except Exception:  # noqa: BLE001 - encerramento nunca falha a aplicação
            pass
        self.transport.close()


class OpenBaoProvider(VaultProvider):
    """OpenBao: herda o adapter do Vault **sem mudar nenhuma linha** de lógica.

    É a prova de que a abstração funciona: OpenBao é um fork open source
    (MPL 2.0) do Vault e mantém a mesma API (AppRole, KV v2, namespaces).
    """

    name = "openbao"
