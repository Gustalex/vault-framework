"""Autenticação por token estático (útil em laboratório e em microserviços
que recebem o token do cliente a cada requisição)."""

from __future__ import annotations

from ...http import IVaultTransport
from .interfaces import AuthToken, IAuthenticator, ITokenProvider


class StaticTokenAuthenticator(IAuthenticator):
    """Usa um token já emitido; ``login`` apenas o devolve."""

    method = "token"

    def __init__(self, transport: IVaultTransport, token: str):
        self._transport = transport
        self._token = token

    def login(self) -> AuthToken:
        return AuthToken(value=self._token)

    def renew(self, token: AuthToken) -> AuthToken:
        return token

    def revoke(self, token: AuthToken) -> None:
        self._transport.request("POST", "auth/token/revoke-self", token=token.value, json_body={})

    def lookup(self, token: AuthToken) -> dict:
        data = self._transport.request("GET", "auth/token/lookup-self", token=token.value).get("data") or {}
        return {k: data.get(k) for k in ("display_name", "policies", "ttl", "renewable", "meta", "entity_id")}


class StaticTokenProvider(ITokenProvider):
    """:class:`ITokenProvider` que sempre entrega o mesmo token.

    Usado pelo *secret-service*: o token chega do cliente no header
    ``X-Vault-Token`` e a policy dele é aplicada pelo próprio cofre.
    """

    def __init__(self, token: str):
        self._token = token

    def get_token(self) -> str:
        return self._token
