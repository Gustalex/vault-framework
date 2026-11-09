"""Mascaramento de dados sensíveis para logs, auditoria e exceções.

Regra do projeto: nenhum token, ``secret_id`` ou senha aparece em log,
evento de auditoria ou mensagem de erro.
"""

from __future__ import annotations

from typing import Any

MASK = "***"

SENSITIVE_HINTS = (
    "token",
    "secret_id",
    "role_id",
    "password",
    "senha",
    "accessor",
    "api_key",
    "apikey",
    "private",
    "authorization",
    "credential",
)


SAFE_KEYS = {"token_policies", "token_type", "token_ttl", "token_max_ttl", "token_num_uses"}


def is_sensitive(key: str) -> bool:
    """Indica se um nome de campo/header deve ter o valor mascarado."""
    lowered = key.lower()
    if lowered in SAFE_KEYS:
        return False
    return any(hint in lowered for hint in SENSITIVE_HINTS)


def mask(obj: Any, *, mask_all_values_under: tuple[str, ...] = ("data",)) -> Any:
    """Devolve uma cópia de ``obj`` com valores sensíveis trocados por ``***``.

    ``mask_all_values_under`` lista chaves cujo conteúdo é sempre segredo
    (no KV v2, ``data.data`` guarda os valores), então tudo abaixo delas é mascarado,
    mesmo que o nome do campo pareça inofensivo.
    """
    if isinstance(obj, dict):
        if "path" in obj and isinstance(obj.get("data"), dict):
            # resposta do secret-service/gateway: {"path": ..., "data": {chave: valor}}
            return {**mask({k: v for k, v in obj.items() if k != "data"}), "data": _mask_values(obj["data"])}
        out: dict[str, Any] = {}
        for k, v in obj.items():
            if is_sensitive(str(k)) and v not in (None, "", [], {}):
                out[k] = MASK
            elif k in mask_all_values_under and isinstance(v, dict) and "data" in v:
                # resposta do KV v2: {"data": {"data": {...}, "metadata": {...}}}
                out[k] = {**mask(v), "data": _mask_values(v["data"])}
            else:
                out[k] = mask(v, mask_all_values_under=mask_all_values_under)
        return out
    if isinstance(obj, list):
        return [mask(i, mask_all_values_under=mask_all_values_under) for i in obj]
    return obj


def _mask_values(d: Any) -> Any:
    if isinstance(d, dict):
        return {k: MASK for k in d}
    return MASK if d is not None else None
