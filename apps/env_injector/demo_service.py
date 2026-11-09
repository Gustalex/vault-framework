"""Processo de exemplo que só conhece variáveis de ambiente (12-factor).

Não sabe que existe cofre: o *env-injector* busca os segredos e os injeta.
"""

import os

print("demo_service iniciado com configuração vinda do ambiente:")
for name in ("APP_ENV", "MERCHANT_ID", "FEATURE_FLAGS", "API_KEY", "SMTP_PASSWORD", "PAYMENT_TOKEN"):
    value = os.environ.get(name)
    shown = value if name in ("APP_ENV", "MERCHANT_ID", "FEATURE_FLAGS") else (f"*** ({len(value)} chars recebidos)" if value else None)
    print(f"  {name:<14} = {shown}")
