"""Gerenciador de sessão: mantém um token válido (login, renovação, revogação)."""

from __future__ import annotations

import threading

from ...errors import VaultKitError
from .interfaces import AuthToken, IAuthenticator, ITokenProvider


class TokenManager(ITokenProvider):
    """Implementa :class:`ITokenProvider` sobre qualquer :class:`IAuthenticator`.

    * faz login preguiçoso na primeira chamada;
    * renova quando falta menos de 20% do TTL;
    * ``invalidate()`` força novo login (usado quando o cofre responde 403 a um
      token expirado);
    * thread-safe, para ser compartilhado entre requisições.
    """

    def __init__(self, authenticator: IAuthenticator, renew_skew: float = 0.2):
        self.authenticator = authenticator
        self._skew = renew_skew
        self._token: AuthToken | None = None
        self._lock = threading.Lock()

    @property
    def current(self) -> AuthToken | None:
        return self._token

    def get_token(self) -> str:
        with self._lock:
            if self._token is None:
                self._token = self.authenticator.login()
            elif self._token.is_expiring(self._skew):
                self._token = self.authenticator.renew(self._token)
            return self._token.value

    def is_valid(self) -> bool:
        """Confere no cofre (``lookup-self``) se o token atual ainda vale.

        Usado depois de um 403 para separar "token expirado/revogado" (refazer
        login) de "policy não permite" (erro legítimo, não adianta repetir).
        """
        token = self._token
        if token is None:
            return False
        try:
            self.authenticator.lookup(token)
            return True
        except VaultKitError:
            return False

    def invalidate(self) -> None:
        with self._lock:
            self._token = None

    def revoke(self) -> None:
        """Revoga o token no cofre (encerramento limpo da sessão)."""
        with self._lock:
            if self._token is not None and self.authenticator.method != "token":
                try:
                    self.authenticator.revoke(self._token)
                finally:
                    self._token = None
