"""Aplicação 2 — **Env Injector** (injeção de segredos em variáveis de ambiente).

Lê um template ``NOME=vault:caminho#chave``, busca cada valor no cofre reutilizando o
framework VaultKit e executa um comando com as variáveis injetadas — o processo filho
não sabe que existe cofre (12-factor app). Nada é gravado em disco.

Hotspots implementados
----------------------
* ``load_references``     → interpreta o arquivo de template;
* ``parse_reference``     → remove o esquema ``vault:`` e exige ``#chave``;
* ``transform``           → extrai a chave pedida e converte em ``str``;
* ``consume``             → executa o comando com o ambiente montado (ou mostra prévia);
* ``create_cache``        → cache maior (300 s), pois o processo reaproveita leituras;
* ``create_audit_sink``   → envia a auditoria ao audit-service **e** ao log local.

Uso::

    python -m apps.env_injector.main -- python apps/env_injector/demo_service.py
    python -m apps.env_injector.main --dry-run          # só mostra as variáveis (mascaradas)
    python -m apps.env_injector.main --direct --dry-run # direto no OpenBao
"""

from __future__ import annotations

import argparse
import logging
import os
import subprocess
from pathlib import Path

from vaultkit import (
    IAuditSink, InvalidReferenceError, ISecretCache, Secret, SecretAccessFramework, SecretProvider, SecretRef,
    VaultConfig, get_provider,
)
from vaultkit.components.audit import CompositeAuditSink, HttpAuditSink, LoggingAuditSink
from vaultkit.components.cache import TTLSecretCache
from vaultkit.config import load_env_file

HERE = Path(__file__).resolve().parent
ROOT = HERE.parent.parent
SCHEME = "vault:"


class EnvInjector(SecretAccessFramework[str, int]):
    """Monta o ambiente a partir do template e executa o comando."""

    app_name = "env-injector"

    def __init__(self, config: VaultConfig, template: Path, command: list[str], dry_run: bool = False,
                 direct: bool = False, **kw):
        self.template = template
        self.command = command
        self.dry_run = dry_run
        self.direct = direct
        self.literals: dict[str, str] = {}
        super().__init__(config, **kw)

    # ---------------- hotspots abstratos ----------------
    def load_references(self) -> dict[str, str]:
        """HOTSPOT: NOME=vault:caminho#chave vai ao cofre; NOME=valor é literal."""
        refs: dict[str, str] = {}
        for n, line in enumerate(self.template.read_text().splitlines(), 1):
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "=" not in line:
                raise InvalidReferenceError(f"{self.template.name}:{n}: esperado NOME=valor")
            name, value = (p.strip() for p in line.split("=", 1))
            if value.startswith(SCHEME):
                refs[name] = value
            else:
                self.literals[name] = value  # valor comum, não vem do cofre
        return refs

    def transform(self, alias: str, ref: SecretRef, secret: Secret) -> str:
        """HOTSPOT: cada variável recebe o valor da chave pedida, como texto."""
        return str(secret.value(ref.key))

    def consume(self, items: dict[str, str]) -> int:
        """HOTSPOT: executa o comando com o ambiente montado (ou só mostra, mascarado)."""
        env = {**self.literals, **items}
        if self.dry_run or not self.command:
            print(f"\nEnv Injector · {len(items)} segredo(s) do cofre + {len(self.literals)} valor(es) literal(is)")
            for k in env:
                origin = "cofre" if k in items else "literal"
                shown = env[k] if origin == "literal" else f"*** ({len(env[k])} chars)"
                print(f"  {k:<16} {origin:<8} {shown}")
            return 0
        print(f"env-injector: executando {' '.join(self.command)} com {len(env)} variável(is)\n", flush=True)
        return subprocess.call(self.command, env={**os.environ, **env})

    # ---------------- hooks / factory methods ----------------
    def parse_reference(self, raw: str) -> SecretRef:
        """HOOK: remove o esquema vault: e exige a chave."""
        ref = SecretRef.parse(raw.removeprefix(SCHEME))
        if not ref.key:
            raise InvalidReferenceError(f"{raw!r}: informe a chave com #CHAVE")
        return ref

    def create_cache(self) -> ISecretCache:
        """FACTORY METHOD: várias variáveis leem o mesmo segredo → cache maior."""
        return TTLSecretCache(ttl=300)

    def create_audit_sink(self) -> IAuditSink:
        """FACTORY METHOD: auditoria no log local e no audit-service."""
        sinks: list[IAuditSink] = [LoggingAuditSink()]
        if not self.direct:
            sinks.append(HttpAuditSink("http://127.0.0.1:8803"))
        return CompositeAuditSink(sinks)

    def create_provider(self) -> SecretProvider:
        """FACTORY METHOD: microserviços (padrão) ou OpenBao direto (--direct)."""
        return get_provider(self.config.with_overrides(provider="openbao" if self.direct else "gateway"))


def main(argv: list[str] | None = None) -> int:
    p = argparse.ArgumentParser(description="Executa um comando com segredos do OpenBao no ambiente")
    p.add_argument("--template", type=Path, default=HERE / "app.env.template")
    p.add_argument("--dry-run", action="store_true", help="só lista as variáveis (mascaradas)")
    p.add_argument("--direct", action="store_true", help="fala direto com o OpenBao (sem microserviços)")
    p.add_argument("--verbose", action="store_true")
    p.add_argument("command", nargs=argparse.REMAINDER, help="comando após --")
    args = p.parse_args(argv)
    logging.basicConfig(level=logging.INFO if args.verbose else logging.WARNING, format="%(message)s")
    load_env_file(str(ROOT / ".lab" / "env-injector.env"))
    command = args.command[1:] if args.command[:1] == ["--"] else args.command
    config = VaultConfig.from_env().with_overrides(verbose=args.verbose)
    return EnvInjector(config, args.template, command, dry_run=args.dry_run, direct=args.direct).execute()


if __name__ == "__main__":
    raise SystemExit(main())
