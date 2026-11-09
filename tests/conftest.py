"""Fixtures compartilhadas: cofre simulado (httpx.MockTransport) e relógio falso."""

from __future__ import annotations

import json

import httpx
import pytest

from vaultkit import VaultConfig


class FakeBao:
    """OpenBao em memória que entende AppRole, KV v2, lookup e revoke."""

    def __init__(self):
        self.secrets: dict[str, list[dict]] = {"apps/db/main": [{"username": "u1", "password": "p1"}]}
        self.allowed_prefix = "apps/"
        self.valid_tokens: set[str] = set()
        self.calls: list[tuple[str, str, dict]] = []
        self.logins = 0

    def handler(self, request: httpx.Request) -> httpx.Response:
        path = request.url.path.removeprefix("/v1/")
        self.calls.append((request.method, path, dict(request.headers)))
        token = request.headers.get("x-vault-token")
        if path == "auth/approle/login":
            body = json.loads(request.content)
            if body.get("secret_id") != "good":
                return httpx.Response(400, json={"errors": ["invalid role or secret ID"]})
            self.logins += 1
            tok = f"tok-{self.logins}"
            self.valid_tokens.add(tok)
            return httpx.Response(200, json={"auth": {"client_token": tok, "token_policies": ["default", "app"],
                                                      "lease_duration": 600, "renewable": True}})
        if path == "sys/health":
            return httpx.Response(200, json={"initialized": True, "sealed": False, "version": "2.7.0"})
        if token not in self.valid_tokens:
            return httpx.Response(403, json={"errors": ["permission denied"]})
        if path == "auth/token/lookup-self":
            return httpx.Response(200, json={"data": {"policies": ["app"], "ttl": 500}})
        if path == "auth/token/revoke-self":
            self.valid_tokens.discard(token)
            return httpx.Response(204)
        if path.startswith("secret/data/"):
            sp = path.removeprefix("secret/data/")
            if not sp.startswith(self.allowed_prefix):
                return httpx.Response(403, json={"errors": ["1 error occurred:\n\t* permission denied\n\n"]})
            if request.method == "POST":
                self.secrets.setdefault(sp, []).append(json.loads(request.content)["data"])
                return httpx.Response(200, json={"data": {"version": len(self.secrets[sp])}})
            versions = self.secrets.get(sp)
            if not versions:
                return httpx.Response(404, json={"errors": []})
            v = int(request.url.params.get("version") or len(versions))
            return httpx.Response(200, json={"data": {"data": versions[v - 1], "metadata": {
                "version": v, "created_time": "2026-11-08T00:00:00Z"}}})
        return httpx.Response(404, json={"errors": []})


@pytest.fixture
def fake_bao() -> FakeBao:
    return FakeBao()


@pytest.fixture
def mock_transport(fake_bao: FakeBao) -> httpx.MockTransport:
    return httpx.MockTransport(fake_bao.handler)


@pytest.fixture
def config() -> VaultConfig:
    return VaultConfig(address="http://bao.test", allow_http=True, role_id="r", secret_id="good",
                       namespace="vaultkit", cache_ttl=60)


class FakeClock:
    def __init__(self):
        self.now = 1000.0

    def __call__(self) -> float:
        return self.now


@pytest.fixture
def clock() -> FakeClock:
    return FakeClock()
