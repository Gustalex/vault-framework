import pytest

from vaultkit import ConfigurationError, InvalidReferenceError, SecretRef, VaultConfig
from vaultkit.masking import mask


@pytest.mark.parametrize("raw,expected", [
    ("apps/db", SecretRef("apps/db")),
    ("apps/db#password", SecretRef("apps/db", "password")),
    ("secret:apps/db#password@2", SecretRef("apps/db", "password", 2, "secret")),
    ("/apps/db/@3", SecretRef("apps/db", None, 3)),
])
def test_parse_reference(raw, expected):
    assert SecretRef.parse(raw) == expected


@pytest.mark.parametrize("raw", ["", "  ", "apps/../root", "a b", "apps/db#", "apps/db@x"])
def test_parse_reference_invalid(raw):
    with pytest.raises(InvalidReferenceError):
        SecretRef.parse(raw)


def test_reference_roundtrip_and_cache_key():
    ref = SecretRef.parse("apps/db#password@2").with_mount("secret")
    assert str(ref) == "secret:apps/db#password@2"
    assert ref.cache_key() == "secret:apps/db@2"  # a chave não muda o cache: o segredo é o mesmo


def test_mask_hides_tokens_and_kv_values_but_keeps_metadata():
    body = {"auth": {"client_token": "s.abc", "accessor": "x", "token_policies": ["default"]},
            "data": {"data": {"username": "deploy", "password": "p"}, "metadata": {"version": 2}}}
    m = mask(body)
    assert m["auth"]["client_token"] == "***" and m["auth"]["accessor"] == "***"
    assert m["auth"]["token_policies"] == ["default"]
    assert m["data"]["data"] == {"username": "***", "password": "***"}
    assert m["data"]["metadata"] == {"version": 2}
    assert body["auth"]["client_token"] == "s.abc"  # original intacto


def test_config_rejects_http_without_flag():
    with pytest.raises(ConfigurationError, match="http://"):
        VaultConfig(address="http://x", role_id="r", secret_id="s").validate()


def test_config_requires_credentials():
    with pytest.raises(ConfigurationError, match="role_id"):
        VaultConfig(address="https://x").validate()
    VaultConfig(address="https://x", auth_method="token", token="t").validate()


def test_config_from_env():
    cfg = VaultConfig.from_env({"VAULTKIT_ADDR": "https://bao:8200/", "VAULTKIT_NAMESPACE": "lab/dados",
                                "VAULTKIT_ALLOW_HTTP": "sim", "VAULTKIT_CACHE_TTL": "5"})
    assert cfg.address == "https://bao:8200" and cfg.namespace == "lab/dados"
    assert cfg.allow_http is True and cfg.cache_ttl == 5.0


def test_config_repr_hides_secrets():
    assert "good" not in repr(VaultConfig(role_id="r", secret_id="good", token="t0k"))
