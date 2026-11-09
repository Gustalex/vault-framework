"""Integração contra o OpenBao real (OrbStack :8210) e a stack docker compose (:8800).

Requer ``python -m scripts.provision`` antes. Os testes são pulados se o cofre
ou o gateway não estiverem no ar.
"""

from pathlib import Path

import httpx
import pytest

from vaultkit import PermissionDeniedError, SecretRef, VaultConfig, get_provider
from vaultkit.config import load_env_file

ROOT = Path(__file__).resolve().parent.parent


def _up(url: str) -> bool:
    try:
        return httpx.get(url, timeout=2).status_code < 500
    except httpx.HTTPError:
        return False


def _cfg(role: str, **kw) -> VaultConfig:
    env = load_env_file(str(ROOT / ".lab" / f"{role}.env"), override=False)
    if not env:
        pytest.skip("rode python -m scripts.provision")
    return VaultConfig.from_env({**env}).with_overrides(**kw)


bao = pytest.mark.skipif(not _up("http://127.0.0.1:8210/v1/sys/health"), reason="OpenBao fora do ar")
gateway = pytest.mark.skipif(not _up("http://127.0.0.1:8800/health"), reason="gateway fora do ar")


@bao
@pytest.mark.parametrize("provider", ["openbao", "vault"])
def test_direct_provider_reads_and_policy_is_enforced(provider):
    with get_provider(_cfg("env-injector", provider=provider)) as p:
        assert p.health()["status"] == "ok"
        s = p.get_secret(SecretRef("apps/env-injector/config", mount="secret"))
        assert s.value("API_KEY").startswith("ak_")
        with pytest.raises(PermissionDeniedError):
            p.get_secret(SecretRef("apps/db-checker/postgres", mount="secret"))


@gateway
def test_gateway_provider_reads_through_microservices():
    with get_provider(_cfg("db-checker", provider="gateway")) as p:
        assert p.health()["status"] == "ok"
        s = p.get_secret(SecretRef("apps/db-checker/postgres", mount="secret"))
        assert s.value("username") == "app_reader"


@gateway
def test_apps_run_against_real_stack():
    from apps.db_checker.main import DbConnectionChecker
    from apps.env_injector.main import EnvInjector

    results = DbConnectionChecker(_cfg("db-checker"), ROOT / "apps/db_checker/targets.json").execute()
    by_name = {r.target: r for r in results}
    assert by_name["postgres-lab"].ok  # senha atual do cofre funciona
    assert not by_name["postgres-lab-v1"].ok  # versão antiga foi rotacionada

    code = EnvInjector(_cfg("env-injector"), ROOT / "apps/env_injector/app.env.template", [], dry_run=True).execute()
    assert code == 0
