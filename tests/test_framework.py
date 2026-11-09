"""Testes do Template Method: ordem dos passos, hotspots, cache, auditoria e erros."""

import pytest

from vaultkit import (
    InvalidReferenceError, OpenBaoProvider, PermissionDeniedError, Secret, SecretAccessFramework,
    SecretProvider, SecretRef, VaultConfig, VaultKitError, get_provider, registry,
)
from vaultkit.components.audit import MemoryAuditSink
from vaultkit.components.cache import TTLSecretCache


class FakeProvider(SecretProvider):
    name = "fake"

    def __init__(self, data):
        self.data, self.reads, self.closed = data, 0, False

    def get_secret(self, ref):
        self.reads += 1
        if ref.path.startswith("proibido"):
            raise PermissionDeniedError("negado")
        return Secret(ref.path, self.data[ref.path], version=1, mount=ref.mount)

    def close(self):
        self.closed = True


class Recorder(SecretAccessFramework[str, dict]):
    """Aplicação de teste que registra a ordem de chamada dos hotspots."""

    def __init__(self, refs, **kw):
        self.refs, self.trace = refs, []
        super().__init__(VaultConfig(allow_http=True, role_id="r", secret_id="s"), **kw)

    def before_run(self): self.trace.append("before_run")
    def load_references(self): self.trace.append("load_references"); return self.refs
    def parse_reference(self, raw): self.trace.append("parse_reference"); return super().parse_reference(raw)
    def validate_reference(self, alias, ref): self.trace.append("validate_reference")
    def transform(self, alias, ref, secret): self.trace.append("transform"); return secret.value(ref.key)
    def consume(self, items): self.trace.append("consume"); return items
    def on_success(self, result): self.trace.append("on_success")
    def after_run(self): self.trace.append("after_run")


def make(refs, data=None, **kw):
    prov = FakeProvider(data or {"apps/a": {"k": "v1"}, "apps/b": {"x": "1", "y": "2"}})
    audit = MemoryAuditSink()
    return Recorder(refs, provider=prov, audit=audit, **kw), prov, audit


def test_template_method_calls_hotspots_in_order():
    app, prov, _ = make({"a": "apps/a#k"})
    assert app.execute() == {"a": "v1"}
    assert app.trace == ["before_run", "load_references", "parse_reference", "validate_reference",
                         "transform", "consume", "on_success", "after_run"]
    assert prov.closed  # o framework libera o provedor ao final


def test_default_mount_is_applied_and_value_without_key():
    app, _, audit = make({"b": "apps/b"})
    assert app.execute() == {"b": {"x": "1", "y": "2"}}
    assert audit.events[0].resource == "secret:apps/b"


def test_cache_avoids_second_read_and_is_audited():
    app, prov, audit = make({"a1": "apps/a#k", "a2": "apps/a#k"}, cache=TTLSecretCache(60))
    app.execute()
    assert prov.reads == 1
    assert [e.outcome for e in audit.events] == ["success", "cache_hit"]


def test_denied_is_audited_and_on_error_default_reraises():
    app, _, audit = make({"p": "proibido/x"}, data={"proibido/x": {}})
    with pytest.raises(PermissionDeniedError):
        app.execute()
    assert audit.events[-1].outcome == "denied"
    assert app.trace[-1] == "after_run"  # limpeza roda mesmo com erro


def test_on_error_hotspot_can_recover():
    class Tolerant(Recorder):
        def on_error(self, error: VaultKitError):
            return {"erro": type(error).__name__}
    app = Tolerant({"x": "a b c"}, provider=FakeProvider({}), audit=MemoryAuditSink())
    assert app.execute() == {"erro": "InvalidReferenceError"}


def test_audit_never_contains_secret_values():
    app, _, audit = make({"a": "apps/a#k"})
    app.execute()
    dumped = str([e.to_dict() for e in audit.events])
    assert "v1" not in dumped and "apps/a" in dumped


def test_framework_with_openbao_provider_end_to_end(config, mock_transport, fake_bao):
    """O mesmo Template Method sobre o adapter real (cofre simulado por HTTP)."""
    prov = OpenBaoProvider(config, http_transport=mock_transport)
    app = Recorder({"pw": "apps/db/main#password"}, provider=prov, audit=MemoryAuditSink())
    assert app.execute() == {"pw": "p1"}
    paths = [c[1] for c in fake_bao.calls]
    assert paths == ["auth/approle/login", "secret/data/apps/db/main", "auth/token/revoke-self"]


def test_provider_relogin_once_when_token_was_revoked(config, mock_transport, fake_bao):
    prov = OpenBaoProvider(config, http_transport=mock_transport)
    prov.get_secret(SecretRef("apps/db/main", mount="secret"))
    fake_bao.valid_tokens.clear()  # token expirou/foi revogado no cofre
    assert prov.get_secret(SecretRef("apps/db/main", mount="secret")).value("username") == "u1"
    assert fake_bao.logins == 2


def test_provider_does_not_relogin_on_policy_denial(config, mock_transport, fake_bao):
    prov = OpenBaoProvider(config, http_transport=mock_transport)
    prov.get_secret(SecretRef("apps/db/main", mount="secret"))
    with pytest.raises(PermissionDeniedError):
        prov.get_secret(SecretRef("outro/x", mount="secret"))
    assert fake_bao.logins == 1


def test_registry_factory_and_extension():
    assert {"openbao", "vault", "gateway"} <= set(registry.names())
    cfg = VaultConfig(allow_http=True, role_id="r", secret_id="s")
    assert type(get_provider(cfg)).__name__ == "OpenBaoProvider"
    assert type(get_provider(cfg.with_overrides(provider="vault"))).__name__ == "VaultProvider"

    @registry.register("memoria")
    class MemoryProvider(SecretProvider):
        name = "memoria"
        def __init__(self, config): pass
        def get_secret(self, ref): return Secret(ref.path, {"v": "ok"})

    assert get_provider(cfg.with_overrides(provider="memoria")).get_secret(SecretRef("x")).value() == "ok"


def test_unknown_provider():
    with pytest.raises(VaultKitError, match="não registrado"):
        get_provider(VaultConfig(provider="cofre-x"))


def test_validate_reference_hotspot_blocks():
    class Strict(Recorder):
        def validate_reference(self, alias, ref):
            raise InvalidReferenceError("fora do escopo")
    app = Strict({"a": "apps/a#k"}, provider=FakeProvider({}), audit=MemoryAuditSink())
    with pytest.raises(InvalidReferenceError):
        app.execute()
