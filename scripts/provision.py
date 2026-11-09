"""Provisiona o OpenBao do laboratório (equivalente ao trabalho do time que administra o cofre).

Cria, de forma idempotente, dentro do namespace ``vaultkit``:

* KV v2 em ``secret/``;
* AppRole em ``approle/``;
* policies e roles para cada aplicação (``db-checker``, ``env-injector``, ``dashboard``);
* segredos de exemplo;
* (opcional) o usuário ``app_reader`` no PostgreSQL do laboratório, com senha aleatória
  gravada **somente** no cofre.

Gera ``.lab/<role>.env`` com ``VAULTKIT_ROLE_ID``/``VAULTKIT_SECRET_ID`` de cada aplicação.
Nunca levar este script nem o token root para produção.

Uso::

    python -m scripts.provision              # provisiona tudo
    python -m scripts.provision rotate       # troca a senha do app_reader (nova versão no KV)
"""

from __future__ import annotations

import argparse
import os
import secrets
import string
import sys
from pathlib import Path

import httpx

ROOT = Path(__file__).resolve().parent.parent
LAB_DIR = ROOT / ".lab"

BAO_ADDR = os.environ.get("BAO_ADDR", "http://127.0.0.1:8210")
BAO_TOKEN = os.environ.get("BAO_TOKEN", "root-dev")
NAMESPACE = os.environ.get("BAO_NAMESPACE", "vaultkit")
PG_DSN_ADMIN = os.environ.get("PG_ADMIN_DSN", "postgresql://postgres:postgres-admin@127.0.0.1:5433/postgres")
PG_HOST_FOR_APPS = os.environ.get("PG_HOST_FOR_APPS", "127.0.0.1")
PG_PORT_FOR_APPS = os.environ.get("PG_PORT_FOR_APPS", "5433")

POLICIES = {
    "vaultkit-db-checker": """
path "secret/data/apps/db-checker/*"     { capabilities = ["read"] }
path "secret/metadata/apps/db-checker/*" { capabilities = ["list", "read"] }
""",
    "vaultkit-env-injector": """
path "secret/data/apps/env-injector/*"     { capabilities = ["read"] }
path "secret/metadata/apps/env-injector/*" { capabilities = ["list", "read"] }
""",
    "vaultkit-dashboard": """
path "secret/data/apps/*"     { capabilities = ["create", "read", "update"] }
path "secret/metadata/apps/*" { capabilities = ["list", "read"] }
path "secret/metadata/"       { capabilities = ["list"] }
path "secret/metadata/apps"   { capabilities = ["list"] }
""",
}

ROLES = {
    "db-checker": ["vaultkit-db-checker"],
    "env-injector": ["vaultkit-env-injector"],
    "dashboard": ["vaultkit-dashboard"],
}


def _password(n: int = 24) -> str:
    alphabet = string.ascii_letters + string.digits
    return "".join(secrets.choice(alphabet) for _ in range(n))


class Bao:
    """Cliente mínimo com token root, só para provisionamento."""

    def __init__(self, namespace: str | None):
        headers = {"X-Vault-Token": BAO_TOKEN}
        if namespace:
            headers["X-Vault-Namespace"] = namespace
        self.c = httpx.Client(base_url=BAO_ADDR.rstrip("/") + "/v1/", headers=headers, timeout=10)

    def call(self, method: str, path: str, ok: tuple[int, ...] = (200, 204), **kw) -> dict:
        r = self.c.request(method, path, **kw)
        if r.status_code not in ok:
            raise SystemExit(f"{method} {path} -> {r.status_code}: {r.text[:300]}")
        return r.json() if r.content else {}


def provision_bao() -> dict[str, dict[str, str]]:
    root = Bao(None)
    health = root.call("GET", "sys/health")
    print(f"OpenBao {health.get('version')} em {BAO_ADDR} (selado={health.get('sealed')})")

    existing = root.call("LIST", "sys/namespaces", ok=(200, 404)).get("data", {}).get("keys", [])
    if f"{NAMESPACE}/" not in existing:
        root.call("POST", f"sys/namespaces/{NAMESPACE}")
        print(f"  + namespace {NAMESPACE}")

    ns = Bao(NAMESPACE)
    mounts = ns.call("GET", "sys/mounts").get("data", {})
    if "secret/" not in mounts:
        ns.call("POST", "sys/mounts/secret", json={"type": "kv", "options": {"version": "2"}})
        print("  + KV v2 em secret/")
    auths = ns.call("GET", "sys/auth").get("data", {})
    if "approle/" not in auths:
        ns.call("POST", "sys/auth/approle", json={"type": "approle"})
        print("  + AppRole em approle/")

    for name, hcl in POLICIES.items():
        ns.call("PUT", f"sys/policies/acl/{name}", json={"policy": hcl})
    print(f"  = policies: {', '.join(POLICIES)}")

    creds: dict[str, dict[str, str]] = {}
    for role, policies in ROLES.items():
        ns.call("POST", f"auth/approle/role/{role}", json={
            "token_policies": policies, "token_ttl": "10m", "token_max_ttl": "1h",
            "secret_id_ttl": "0", "token_type": "service",
        })
        role_id = ns.call("GET", f"auth/approle/role/{role}/role-id")["data"]["role_id"]
        secret_id = ns.call("POST", f"auth/approle/role/{role}/secret-id")["data"]["secret_id"]
        creds[role] = {"role_id": role_id, "secret_id": secret_id}
    print(f"  = roles: {', '.join(ROLES)}")

    ns.call("POST", "secret/data/apps/env-injector/config", json={"data": {
        "API_KEY": "ak_" + _password(32), "SMTP_PASSWORD": _password(), "FEATURE_FLAGS": "beta,dark-mode",
        "LOG_LEVEL": "INFO",
    }})
    ns.call("POST", "secret/data/apps/env-injector/payments", json={"data": {
        "GATEWAY_TOKEN": "pk_test_" + _password(24), "MERCHANT_ID": "lab-0042",
    }})
    print("  = segredos de exemplo em secret/apps/env-injector/*")
    return creds


def write_db_secret(password: str) -> int:
    ns = Bao(NAMESPACE)
    body = ns.call("POST", "secret/data/apps/db-checker/postgres", json={"data": {
        "username": "app_reader", "password": password, "host": PG_HOST_FOR_APPS,
        "port": PG_PORT_FOR_APPS, "dbname": "vaultkit_lab",
    }})
    return body["data"]["version"]


def set_pg_password(password: str) -> bool:
    try:
        import psycopg
        from psycopg import sql
    except ImportError:
        print("  ! psycopg não instalado; pulando PostgreSQL")
        return False
    try:
        with psycopg.connect(PG_DSN_ADMIN, autocommit=True, connect_timeout=3) as conn:
            exists = conn.execute("SELECT 1 FROM pg_roles WHERE rolname='app_reader'").fetchone()
            verb = "ALTER" if exists else "CREATE"
            conn.execute(sql.SQL("{} ROLE app_reader WITH LOGIN PASSWORD {}").format(
                sql.SQL(verb), sql.Literal(password)))
            if not conn.execute("SELECT 1 FROM pg_database WHERE datname='vaultkit_lab'").fetchone():
                conn.execute("CREATE DATABASE vaultkit_lab OWNER postgres")
            conn.execute("GRANT CONNECT ON DATABASE vaultkit_lab TO app_reader")
        return True
    except psycopg.OperationalError as exc:
        print(f"  ! PostgreSQL indisponível ({str(exc).splitlines()[0]}); suba com docker compose up -d postgres")
        return False


def write_env_files(creds: dict[str, dict[str, str]]) -> None:
    LAB_DIR.mkdir(exist_ok=True)
    for role, c in creds.items():
        f = LAB_DIR / f"{role}.env"
        f.write_text(
            "# gerado por scripts/provision.py — NÃO versionar\n"
            f"VAULTKIT_ADDR={BAO_ADDR}\nVAULTKIT_NAMESPACE={NAMESPACE}\nVAULTKIT_ALLOW_HTTP=true\n"
            f"VAULTKIT_GATEWAY_URL=http://127.0.0.1:8800\nVAULTKIT_CLIENT_NAME={role}\n"
            f"VAULTKIT_ROLE_ID={c['role_id']}\nVAULTKIT_SECRET_ID={c['secret_id']}\n"
        )
        f.chmod(0o600)
    print(f"  = credenciais AppRole em {LAB_DIR}/<role>.env (role_id/secret_id omitidos aqui)")


def rotate() -> None:
    pw = _password()
    if set_pg_password(pw):
        v = write_db_secret(pw)
        print(f"senha do app_reader trocada no PostgreSQL e gravada no cofre (versão {v})")


def main(argv: list[str] | None = None) -> None:
    p = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    p.add_argument("command", nargs="?", default="all", choices=["all", "rotate"])
    args = p.parse_args(argv)
    if args.command == "rotate":
        return rotate()
    creds = provision_bao()
    pw = _password()
    pg_ok = set_pg_password(pw)
    v = write_db_secret(pw)
    print(f"  = secret/apps/db-checker/postgres versão {v}" + ("" if pg_ok else " (PostgreSQL não configurado)"))
    write_env_files(creds)
    print("pronto.")


if __name__ == "__main__":
    sys.exit(main())
