"""Passo a passo: criando uma nova aplicação a partir do framework VaultKit.

Cenário: um *job* que precisa do token de pagamento para chamar uma API externa.

Passo 1 — o time do cofre cadastra o segredo e um AppRole com policy de leitura
          (no laboratório: ``python -m scripts.provision``).
Passo 2 — a aplicação recebe só ``VAULTKIT_ROLE_ID``/``VAULTKIT_SECRET_ID`` e o
          endereço (``.lab/env-injector.env`` neste exemplo).
Passo 3 — herdar :class:`SecretAccessFramework[T, R]`.
Passo 4 — implementar os 3 hotspots abstratos: ``load_references``,
          ``transform`` e ``consume``.
Passo 5 — (opcional) sobrescrever ganchos/fábricas: ``validate_reference``,
          ``on_error``, ``create_provider``, ``create_cache``, ``create_audit_sink``.
Passo 6 — chamar ``execute()``: o framework faz login, cache, leitura, auditoria,
          mascaramento, tratamento de erros e revoga o token no final.
Passo 7 — testar sem cofre injetando um provedor falso (``provider=...``).
Passo 8 — (extensão) outro cofre = registrar um Adapter com ``@registry.register``.

Executar::

    python -m apps.exemplo_minimo
"""

from __future__ import annotations

from vaultkit import Secret, SecretAccessFramework, SecretRef, VaultConfig
from vaultkit.config import load_env_file


class PaymentJob(SecretAccessFramework[str, str]):          # Passo 3
    app_name = "payment-job"

    def load_references(self) -> dict[str, str]:              # hotspot 1: quais segredos
        return {"token": "apps/env-injector/payments#GATEWAY_TOKEN"}

    def transform(self, alias: str, ref: SecretRef, secret: Secret) -> str:  # hotspot 2: como converter
        return secret.value(ref.key)

    def consume(self, items: dict[str, str]) -> str:          # hotspot 3: o que fazer
        token = items["token"]
        # aqui entraria a chamada real: httpx.post(url, headers={"Authorization": f"Bearer {token}"})
        return f"job executado com token de {len(token)} caracteres (valor nunca impresso)"


if __name__ == "__main__":
    load_env_file(".lab/env-injector.env")                    # Passo 2
    config = VaultConfig.from_env()                           # provider=openbao (direto)
    print(PaymentJob(config).execute())                       # Passo 6
    # Trocar para a arquitetura de microserviços = trocar a estratégia, sem mudar o código:
    print(PaymentJob(config.with_overrides(provider="gateway")).execute())
