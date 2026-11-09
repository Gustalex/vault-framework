"""Teste de carga do VaultKit (Locust).

Dois perfis de usuário:

* ``GatewayUser`` — fluxo completo pelos microserviços (gateway → auth/secret/audit);
* ``DirectUser``  — mesmo segredo lido pelo framework direto no OpenBao, registrado
  como requisição do tipo ``VAULT`` (compara o custo da camada de microserviços).

Executar (com a stack no ar e ``python -m scripts.provision`` feito)::

    locust -f load/locustfile.py --headless -u 20 -r 5 -t 30s --host http://127.0.0.1:8800
"""

from __future__ import annotations

import time
from pathlib import Path

from locust import HttpUser, User, between, events, task

from vaultkit import SecretRef, VaultConfig, VaultKitError, get_provider
from vaultkit.config import load_env_file

ROOT = Path(__file__).resolve().parent.parent
DB = load_env_file(str(ROOT / ".lab" / "db-checker.env"), override=False)
ENV = load_env_file(str(ROOT / ".lab" / "env-injector.env"), override=False)


class GatewayUser(HttpUser):
    weight = 3
    wait_time = between(0.2, 1.0)

    def on_start(self) -> None:
        r = self.client.post("/api/auth/login", name="POST /api/auth/login",
                             json={"role_id": DB["VAULTKIT_ROLE_ID"], "secret_id": DB["VAULTKIT_SECRET_ID"]},
                             headers={"X-Client-Name": "locust"})
        self.h = {"X-Vault-Token": r.json()["auth"]["client_token"], "X-Client-Name": "locust"}

    @task(6)
    def read_secret(self) -> None:
        self.client.get("/api/secrets/secret/apps/db-checker/postgres", headers=self.h,
                        name="GET /api/secrets/[path]")

    @task(2)
    def read_version(self) -> None:
        self.client.get("/api/secrets/secret/apps/db-checker/postgres?version=1", headers=self.h,
                        name="GET /api/secrets/[path]?version")

    @task(1)
    def denied(self) -> None:
        with self.client.get("/api/secrets/secret/apps/env-injector/config", headers=self.h,
                             name="GET /api/secrets [negado]", catch_response=True) as r:
            r.success() if r.status_code == 403 else r.failure(f"esperado 403, veio {r.status_code}")

    @task(1)
    def services(self) -> None:
        self.client.get("/api/services", name="GET /api/services")

    @task(1)
    def audit(self) -> None:
        self.client.get("/api/audit/events?limit=20", name="GET /api/audit/events")

    @task(1)
    def lookup(self) -> None:
        self.client.get("/api/auth/lookup", headers=self.h, name="GET /api/auth/lookup")


class DirectUser(User):
    """Usa o framework (OpenBaoProvider) sem passar pelos microserviços."""

    weight = 1
    wait_time = between(0.2, 1.0)

    def on_start(self) -> None:
        cfg = VaultConfig.from_env(ENV)
        self.provider = get_provider(cfg)
        self.ref = SecretRef("apps/env-injector/config", mount="secret")

    def on_stop(self) -> None:
        self.provider.close()

    @task
    def read_direct(self) -> None:
        t0 = time.perf_counter()
        exc = None
        try:
            self.provider.get_secret(self.ref)
        except VaultKitError as e:
            exc = e
        events.request.fire(request_type="VAULT", name="leitura direta openbao", exception=exc,
                            response_time=(time.perf_counter() - t0) * 1000, response_length=0, context={})
