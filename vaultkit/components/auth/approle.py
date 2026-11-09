"""Autenticação por AppRole (``POST /v1/auth/<mount>/login``)."""

from __future__ import annotations

from ...errors import AuthenticationError
from ...http import IVaultTransport
from .interfaces import AuthToken, IAuthenticator


def token_from_auth(auth: dict | None) -> AuthToken:
    """Converte o bloco ``auth`` da resposta do cofre em :class:`AuthToken`."""
    if not auth or not auth.get("client_token"):
        raise AuthenticationError("resposta de login sem client_token")
    return AuthToken(
        value=auth["client_token"],
        policies=list(auth.get("token_policies") or auth.get("policies") or []),
        ttl=int(auth.get("lease_duration") or 0),
        renewable=bool(auth.get("renewable")),
        accessor=auth.get("accessor"),
    )


class AppRoleAuthenticator(IAuthenticator):
    """Login com ``role_id`` + ``secret_id`` — o "crachá" da aplicação no cofre.

    :param transport: interface requerida para falar com o cofre.
    :param role_id: identificador do papel (não é segredo forte, mas é mascarado).
    :param secret_id: senha do papel.
    :param mount: caminho onde o AppRole está habilitado (padrão ``approle``).
    """

    method = "approle"

    def __init__(self, transport: IVaultTransport, role_id: str, secret_id: str, mount: str = "approle"):
        self._transport = transport
        self._role_id = role_id
        self._secret_id = secret_id
        self._mount = mount.strip("/")

    def login(self) -> AuthToken:
        body = self._transport.request(
            "POST", f"auth/{self._mount}/login",
            json_body={"role_id": self._role_id, "secret_id": self._secret_id},
        )
        return token_from_auth(body.get("auth"))

    def renew(self, token: AuthToken) -> AuthToken:
        if not token.renewable:
            return self.login()
        body = self._transport.request("POST", "auth/token/renew-self", token=token.value, json_body={})
        renewed = token_from_auth(body.get("auth"))
        return renewed

    def revoke(self, token: AuthToken) -> None:
        self._transport.request("POST", "auth/token/revoke-self", token=token.value, json_body={})

    def lookup(self, token: AuthToken) -> dict:
        data = self._transport.request("GET", "auth/token/lookup-self", token=token.value).get("data") or {}
        return {k: data.get(k) for k in ("display_name", "policies", "ttl", "renewable", "meta", "entity_id")}
