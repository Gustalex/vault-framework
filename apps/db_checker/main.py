"""Aplicação 1 — **DB Connection Checker**.

Reutiliza o framework VaultKit para testar a conexão com bancos de dados cujas
credenciais ficam **somente** no cofre. A aplicação guarda apenas *onde* está a
credencial (``credential_ref``), nunca a senha — o mesmo cenário do
``check_target`` descrito na documentação do cofre.

Hotspots implementados
----------------------
* ``load_references``     → lê os alvos de ``targets.json``;
* ``parse_reference``     → aceita o prefixo ``pg:`` além do formato padrão;
* ``validate_reference``  → só permite caminhos ``apps/db-checker/*``;
* ``transform``           → converte o segredo em :class:`DbCredentials`;
* ``consume``             → conecta no PostgreSQL e roda ``SELECT current_user, version()``;
* ``on_error``            → devolve relatório de falha em vez de quebrar;
* ``create_provider``     → ``--direct`` usa o OpenBao direto; padrão: via API Gateway.

Uso::

    python -m apps.db_checker.main                 # via microserviços (gateway :8800)
    python -m apps.db_checker.main --direct        # direto no OpenBao
    python -m apps.db_checker.main --verbose       # mostra as chamadas (mascaradas)
"""

from __future__ import annotations

import argparse
import json
import logging
import re
import time
from dataclasses import dataclass, field
from pathlib import Path

import psycopg

from vaultkit import (
    InvalidReferenceError, Secret, SecretAccessFramework, SecretProvider, SecretRef, VaultConfig, VaultKitError,
    get_provider,
)
from vaultkit.config import load_env_file

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent


@dataclass
class DbCredentials:
    """Credencial de banco pronta para uso. A senha não aparece no ``repr``."""

    target: str
    host: str
    port: int
    dbname: str
    username: str
    password: str = field(repr=False)
    version: int | None = None


@dataclass
class CheckResult:
    target: str
    ok: bool
    detail: str
    latency_ms: float
    secret_version: int | None = None


class DbConnectionChecker(SecretAccessFramework[DbCredentials, list[CheckResult]]):
    """Verifica a conexão com cada alvo de ``targets.json``."""

    app_name = "db-checker"
    ALLOWED_PREFIX = "apps/db-checker/"

    def __init__(self, config: VaultConfig, targets_file: Path, direct: bool = False, **kw):
        self.targets_file = targets_file
        self.direct = direct
        self.targets: dict[str, dict] = {}
        super().__init__(config, **kw)

    # ---------------- hotspots abstratos ----------------
    def load_references(self) -> dict[str, str]:
        """HOTSPOT: os alvos vêm de um JSON; cada um guarda só ONDE está a credencial."""
        self.targets = {t["name"]: t for t in json.loads(self.targets_file.read_text())}
        return {name: t["credential_ref"] for name, t in self.targets.items()}

    def transform(self, alias: str, ref: SecretRef, secret: Secret) -> DbCredentials:
        """HOTSPOT: o segredo do KV vira uma credencial de banco tipada."""
        d = secret.data
        return DbCredentials(target=alias, host=d.get("host", "127.0.0.1"), port=int(d.get("port", 5432)),
                             dbname=d.get("dbname", "postgres"), username=d["username"],
                             password=d["password"], version=secret.version)

    def consume(self, items: dict[str, DbCredentials]) -> list[CheckResult]:
        """HOTSPOT: conecta em cada banco e roda uma consulta de verificação."""
        results = []
        for name, creds in items.items():
            t0 = time.perf_counter()
            try:
                with psycopg.connect(host=creds.host, port=creds.port, dbname=creds.dbname, user=creds.username,
                                     password=creds.password, connect_timeout=5) as conn:
                    user, version = conn.execute("SELECT current_user, version()").fetchone()
                results.append(CheckResult(name, True, f"conectado como {user} · {version.split(',')[0]}",
                                           self._ms(t0), creds.version))
            except psycopg.Error as exc:
                msg = re.sub(r".*FATAL:\s*", "FATAL: ", str(exc).strip().splitlines()[-1])[:120]
                results.append(CheckResult(name, False, msg, self._ms(t0), creds.version))
        return results

    # ---------------- ganchos ----------------
    def parse_reference(self, raw: str) -> SecretRef:
        """GANCHO: aceita referências no formato pg:apps/db-checker/x."""
        return SecretRef.parse(raw.removeprefix("pg:"))

    def validate_reference(self, alias: str, ref: SecretRef) -> None:
        """GANCHO: a aplicação só pode ler caminhos do próprio escopo."""
        if not ref.path.startswith(self.ALLOWED_PREFIX):
            raise InvalidReferenceError(f"{alias}: referência fora de {self.ALLOWED_PREFIX}")

    def on_error(self, error: VaultKitError) -> list[CheckResult]:
        """GANCHO: em vez de quebrar, devolve uma linha de falha no relatório."""
        return [CheckResult("*", False, f"{type(error).__name__}: {error}", 0.0)]

    def create_provider(self) -> SecretProvider:
        """FACTORY METHOD: microserviços (padrão) ou OpenBao direto (--direct)."""
        return get_provider(self.config.with_overrides(provider="openbao" if self.direct else "gateway"))


def print_report(results: list[CheckResult], mode: str) -> None:
    print(f"\nDB Connection Checker · modo {mode}\n" + "-" * 78)
    print(f"{'alvo':<18} {'ok':<4} {'versão':<7} {'ms':>7}  detalhe")
    for r in results:
        print(f"{r.target:<18} {'sim' if r.ok else 'NÃO':<4} {str(r.secret_version or '-'):<7} {r.latency_ms:>7.1f}  {r.detail}")
    print("-" * 78)


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Testa conexões com bancos cujas senhas estão no OpenBao")
    p.add_argument("--targets", type=Path, default=HERE / "targets.json")
    p.add_argument("--direct", action="store_true", help="fala direto com o OpenBao (sem microserviços)")
    p.add_argument("--verbose", action="store_true")
    args = p.parse_args(argv)
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING, format="%(message)s")
    load_env_file(str(ROOT / ".lab" / "db-checker.env"))
    config = VaultConfig.from_env().with_overrides(verbose=args.verbose)
    results = DbConnectionChecker(config, args.targets, direct=args.direct).execute()
    print_report(results, "direto (OpenBaoProvider)" if args.direct else "microserviços (GatewayProvider)")
    return 0 if all(r.ok for r in results) else 1


if __name__ == "__main__":
    raise SystemExit(main())
