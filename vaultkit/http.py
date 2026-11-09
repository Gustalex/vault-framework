"""Transporte HTTP comum a todos os componentes (interface requerida ``IVaultTransport``).

Centraliza o que não pode variar entre componentes: timeout, verificação de TLS,
header de namespace, mapeamento de status HTTP para erros do framework e log
``--verbose`` com valores mascarados.
"""

from __future__ import annotations

import json
import logging
import re
from typing import Any, Protocol

import httpx

from .config import VaultConfig
from .errors import (
    AuthenticationError,
    PermissionDeniedError,
    SecretNotFoundError,
    VaultKitError,
    VaultUnavailableError,
)
from .masking import mask

log = logging.getLogger("vaultkit.http")
logging.getLogger("httpx").setLevel(logging.WARNING)


class IVaultTransport(Protocol):
    """Interface requerida pelos componentes para falar com o cofre."""

    def request(
        self, method: str, path: str, *, json_body: Any = None, token: str | None = None,
        params: dict | None = None, use_namespace: bool = True,
    ) -> dict: ...

    def close(self) -> None: ...


class VaultHttpClient:
    """Implementação de :class:`IVaultTransport` sobre ``httpx``.

    :param config: configuração (endereço, namespace, TLS, timeout, verbose).
    :param transport: transporte ``httpx`` alternativo (usado nos testes).
    """

    def __init__(self, config: VaultConfig, transport: httpx.BaseTransport | None = None,
                 base_url: str | None = None):
        self.config = config
        self._client = httpx.Client(
            base_url=(base_url or config.address).rstrip("/"),
            timeout=config.timeout,
            verify=config.verify_tls,
            transport=transport,
            headers={"User-Agent": f"vaultkit/{config.client_name}"},
        )

    # ------------------------------------------------------------------ #
    def request(self, method: str, path: str, *, json_body: Any = None, token: str | None = None,
                params: dict | None = None, use_namespace: bool = True) -> dict:
        """Executa a chamada e devolve o JSON (``{}`` para respostas 204).

        ``use_namespace=False`` omite o header de namespace (``sys/health`` só
        existe no namespace raiz).

        :raises AuthenticationError: 400/401 no login ou token inválido.
        :raises PermissionDeniedError: 403.
        :raises SecretNotFoundError: 404.
        :raises VaultUnavailableError: falha de rede, timeout, 5xx ou cofre selado.
        """
        headers: dict[str, str] = {}
        if token:
            headers["X-Vault-Token"] = token
        if self.config.namespace and use_namespace:
            headers["X-Vault-Namespace"] = self.config.namespace
        url = "/v1/" + path.lstrip("/") if not path.startswith("/api") else path
        self._debug_request(method, url, headers, json_body)
        try:
            resp = self._client.request(method, url, json=json_body, headers=headers, params=params)
        except httpx.TimeoutException as exc:
            raise VaultUnavailableError(f"timeout falando com o cofre ({self.config.timeout}s)") from exc
        except httpx.HTTPError as exc:
            raise VaultUnavailableError(f"cofre inacessível: {exc.__class__.__name__}") from exc
        body = self._parse(resp)
        self._debug_response(resp.status_code, body)
        if resp.status_code >= 400:
            raise self._to_error(resp.status_code, body, path)
        return body

    def close(self) -> None:
        self._client.close()

    # ------------------------------------------------------------------ #
    @staticmethod
    def _parse(resp: httpx.Response) -> dict:
        if resp.status_code == 204 or not resp.content:
            return {}
        try:
            data = resp.json()
        except ValueError:
            return {"raw": "<corpo não-JSON omitido>"}
        return data if isinstance(data, dict) else {"data": data}

    @staticmethod
    def _to_error(status: int, body: dict, path: str) -> VaultKitError:
        errors = body.get("errors") or body.get("detail") or []
        reason = "; ".join(map(str, errors)) if isinstance(errors, list) else str(errors)
        # o cofre embrulha erros como "1 error occurred:\n\t* permission denied\n\n"
        reason = re.sub(r"\d+ errors? occurred:", "", reason)
        reason = " ".join(reason.replace("*", " ").split())[:200] or f"HTTP {status}"
        if path.startswith("/api"):
            # resposta do gateway: o microserviço já traduziu o erro, só repassamos
            cls = {401: AuthenticationError, 403: PermissionDeniedError, 404: SecretNotFoundError}.get(
                status, VaultUnavailableError if status >= 500 else VaultKitError)
            err = cls(reason)
            err.status_code = status
            return err
        if status == 404:
            return SecretNotFoundError(f"não encontrado: {path}")
        if status == 403:
            return PermissionDeniedError(f"permissão negada em {path}: {reason}")
        if status in (400, 401) and "login" in path:
            return AuthenticationError(f"login recusado: {reason}")
        if status == 401:
            return AuthenticationError(reason)
        if status >= 500:
            return VaultUnavailableError(f"cofre respondeu {status}: {reason}")
        err = VaultKitError(f"requisição inválida ({status}): {reason}")
        err.status_code = status
        return err

    def _debug_request(self, method: str, url: str, headers: dict, body: Any) -> None:
        if self.config.verbose:
            log.info("-> %s %s%s\nheaders: %s\nbody: %s", method, self._client.base_url, url,
                     json.dumps(mask(headers)), json.dumps(mask(body), indent=2))

    def _debug_response(self, status: int, body: dict) -> None:
        if self.config.verbose:
            log.info("<- HTTP %s\n%s", status, json.dumps(mask(body), indent=2))
