"""Microserviços testados em processo (FastAPI TestClient) com o cofre simulado."""

import importlib

import httpx
import pytest
from fastapi.testclient import TestClient

from vaultkit.http import VaultHttpClient


@pytest.fixture
def services(monkeypatch, fake_bao, config, tmp_path):
    monkeypatch.setenv("AUDIT_DB", str(tmp_path / "audit.db"))
    monkeypatch.delenv("AUDIT_URL", raising=False)
    mods = {}
    for name in ("auth_service", "secret_service", "audit_service"):
        mod = importlib.reload(importlib.import_module(f"services.{name}.main"))
        if hasattr(mod, "transport"):
            mod.transport = VaultHttpClient(config, transport=httpx.MockTransport(fake_bao.handler))
        mods[name] = TestClient(mod.app)
    return mods


def test_auth_login_and_lookup(services):
    auth = services["auth_service"]
    r = auth.post("/login", json={"role_id": "r", "secret_id": "good"})
    assert r.status_code == 200 and r.json()["auth"]["token_policies"] == ["default", "app"]
    tok = r.json()["auth"]["client_token"]
    assert auth.get("/lookup", headers={"X-Vault-Token": tok}).json()["policies"] == ["app"]
    assert auth.post("/login", json={"role_id": "r", "secret_id": "bad"}).status_code == 401
    assert auth.get("/health").json()["dependencies"]["openbao"]["version"] == "2.7.0"


def test_secret_read_cache_write_and_denied(services):
    tok = services["auth_service"].post("/login", json={"role_id": "r", "secret_id": "good"}).json()["auth"]["client_token"]
    sec, h = services["secret_service"], {"X-Vault-Token": tok}
    r1 = sec.get("/secrets/secret/apps/db/main", headers=h).json()
    r2 = sec.get("/secrets/secret/apps/db/main", headers=h).json()
    assert r1["data"]["password"] == "p1" and not r1["cached"] and r2["cached"]
    assert sec.put("/secrets/secret/apps/db/main", headers=h, json={"data": {"password": "p2"}}).json()["version"] == 2
    assert sec.get("/secrets/secret/apps/db/main", headers=h).json()["data"]["password"] == "p2"  # cache invalidado
    assert sec.get("/secrets/secret/apps/db/main?version=1", headers=h).json()["data"]["password"] == "p1"
    assert sec.get("/secrets/secret/outro/x", headers=h).status_code == 403
    assert sec.get("/secrets/secret/apps/db/main").status_code == 422  # sem token


def test_audit_service_roundtrip(services):
    a = services["audit_service"]
    assert a.post("/events", json={"action": "secret.read", "resource": "secret:x", "service": "t",
                                   "detail": {"password": "nunca"}}).status_code == 201
    ev = a.get("/events").json()["events"][0]
    assert ev["detail"]["password"] == "***"
    assert a.get("/stats").json()["total"] == 1


def test_gateway_routes_table():
    gw = importlib.import_module("services.gateway.main")
    client = TestClient(gw.app)
    prefixes = {r["prefix"]: r["service"] for r in client.get("/api/routes").json()["routes"]}
    assert prefixes["/api/auth/*"] == "auth-service" and prefixes["/api/secrets/*"] == "secret-service"
    assert client.get("/api/desconhecida/x").status_code == 404
    assert "VaultKit" in client.get("/").text
