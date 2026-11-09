"""Testes de cada componente isolado (interfaces providas/requeridas)."""

import json
import logging

import httpx
import pytest

from vaultkit import AuthenticationError, PermissionDeniedError, SecretNotFoundError, VaultUnavailableError
from vaultkit.components.audit import (
    AuditEvent, CompositeAuditSink, HttpAuditSink, LoggingAuditSink, MemoryAuditSink, SQLiteAuditSink,
)
from vaultkit.components.auth import AppRoleAuthenticator, AuthToken, StaticTokenProvider, TokenManager
from vaultkit.components.cache import NullCache, TTLSecretCache
from vaultkit.components.secrets import KVv2SecretStore
from vaultkit.http import VaultHttpClient


# ---------------- auth ----------------
def test_approle_login_sends_namespace_and_parses_token(config, mock_transport, fake_bao):
    t = VaultHttpClient(config, transport=mock_transport)
    token = AppRoleAuthenticator(t, "r", "good").login()
    assert token.value == "tok-1" and token.policies == ["default", "app"] and token.ttl == 600
    assert "tok-1" not in repr(token)
    assert fake_bao.calls[0][2]["x-vault-namespace"] == "vaultkit"


def test_approle_bad_secret_raises_authentication_error(config, mock_transport):
    t = VaultHttpClient(config, transport=mock_transport)
    with pytest.raises(AuthenticationError):
        AppRoleAuthenticator(t, "r", "bad").login()


def test_token_manager_lazy_login_reuse_and_revoke(config, mock_transport, fake_bao):
    t = VaultHttpClient(config, transport=mock_transport)
    mgr = TokenManager(AppRoleAuthenticator(t, "r", "good"))
    assert fake_bao.logins == 0
    assert mgr.get_token() == mgr.get_token() == "tok-1"
    assert fake_bao.logins == 1 and mgr.is_valid()
    mgr.revoke()
    assert "tok-1" not in fake_bao.valid_tokens and mgr.current is None


def test_auth_token_expiry():
    tok = AuthToken("x", ttl=100, obtained_at=0)
    assert not tok.is_expiring(now=50) and tok.is_expiring(now=85)
    assert AuthToken("root").expires_in() == float("inf")


# ---------------- secrets ----------------
def test_kv2_read_write_versions(config, mock_transport, fake_bao):
    t = VaultHttpClient(config, transport=mock_transport)
    store = KVv2SecretStore(t, TokenManager(AppRoleAuthenticator(t, "r", "good")))
    s = store.read("apps/db/main")
    assert s.value("password") == "p1" and s.version == 1 and "p1" not in repr(s)
    assert store.write("apps/db/main", {"username": "u1", "password": "p2"}) == 2
    assert store.read("apps/db/main").value("password") == "p2"
    assert store.read("apps/db/main", version=1).value("password") == "p1"


def test_kv2_errors_are_translated(config, mock_transport):
    t = VaultHttpClient(config, transport=mock_transport)
    store = KVv2SecretStore(t, TokenManager(AppRoleAuthenticator(t, "r", "good")))
    with pytest.raises(SecretNotFoundError):
        store.read("apps/nao-existe")
    with pytest.raises(PermissionDeniedError, match="permission denied$"):
        store.read("outro/segredo")
    with pytest.raises(SecretNotFoundError):
        store.read("apps/db/main").value("nao-tem")


def test_transport_unavailable(config):
    def boom(request):
        raise httpx.ConnectError("refused")
    t = VaultHttpClient(config, transport=httpx.MockTransport(boom))
    with pytest.raises(VaultUnavailableError):
        KVv2SecretStore(t, StaticTokenProvider("x")).read("a")


def test_verbose_log_is_masked(config, mock_transport, caplog):
    t = VaultHttpClient(config.with_overrides(verbose=True), transport=mock_transport)
    with caplog.at_level(logging.INFO, logger="vaultkit.http"):
        KVv2SecretStore(t, TokenManager(AppRoleAuthenticator(t, "r", "good"))).read("apps/db/main")
    text = caplog.text
    assert "POST" in text and "apps/db/main" in text
    assert "good" not in text and "tok-1" not in text and "p1" not in text


# ---------------- cache ----------------
def test_ttl_cache_expiry_lru_and_stats(clock):
    c = TTLSecretCache(ttl=10, max_entries=2, clock=clock)
    c.put("a", 1)
    assert c.get("a") == 1
    clock.now += 11
    assert c.get("a") is None
    c.put("a", 1); c.put("b", 2); c.get("a"); c.put("c", 3)  # "b" é o menos usado
    assert c.get("b") is None and c.get("a") == 1 and c.get("c") == 3
    assert c.stats()["size"] == 2
    c.invalidate()
    assert c.stats()["size"] == 0


def test_null_cache():
    c = NullCache()
    c.put("a", 1)
    assert c.get("a") is None


# ---------------- audit ----------------
def test_audit_event_masks_detail():
    e = AuditEvent("auth.login", "approle", detail={"secret_id": "s", "policies": ["x"]})
    assert e.detail == {"secret_id": "***", "policies": ["x"]}


def test_sqlite_sink_query_and_stats(tmp_path):
    sink = SQLiteAuditSink(str(tmp_path / "a.db"))
    sink.record(AuditEvent("secret.read", "secret:a", service="s1"))
    sink.record(AuditEvent("secret.read", "secret:b", outcome="denied", service="s2"))
    assert [e["resource"] for e in sink.query()] == ["secret:b", "secret:a"]
    assert len(sink.query(service="s1")) == 1
    assert sink.stats()["by_outcome"] == {"success": 1, "denied": 1}


def test_http_sink_never_raises():
    def boom(request):
        raise httpx.ConnectError("down")
    HttpAuditSink("http://audit", transport=httpx.MockTransport(boom)).record(AuditEvent("a", "b"))


def test_http_sink_posts_event():
    seen = []
    def handler(request):
        seen.append(json.loads(request.content))
        return httpx.Response(201)
    HttpAuditSink("http://audit", transport=httpx.MockTransport(handler)).record(AuditEvent("a", "b"))
    assert seen[0]["action"] == "a"


def test_composite_sink_isolates_failures():
    class Broken(LoggingAuditSink):
        def record(self, event):
            raise RuntimeError("x")
    mem = MemoryAuditSink()
    CompositeAuditSink([Broken(), mem]).record(AuditEvent("a", "b"))
    assert len(mem.events) == 1
