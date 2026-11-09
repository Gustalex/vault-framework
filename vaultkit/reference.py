"""Referência a um segredo: *onde* a credencial está no cofre, nunca o valor.

Formato aceito por :meth:`SecretRef.parse`::

    [mount:]caminho[#chave][@versão]

Exemplos::

    apps/db-checker/postgres               -> mount padrão, segredo inteiro
    apps/db-checker/postgres#password      -> só a chave "password"
    secret:apps/db-checker/postgres#password@2  -> mount "secret", versão 2
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from .errors import InvalidReferenceError

_REF_RE = re.compile(
    r"^(?:(?P<mount>[A-Za-z0-9_\-]+):)?"
    r"(?P<path>[A-Za-z0-9_\-./]+?)"
    r"(?:#(?P<key>[A-Za-z0-9_\-.]+))?"
    r"(?:@(?P<version>\d+))?$"
)


@dataclass(frozen=True)
class SecretRef:
    """Ponteiro imutável para um segredo do KV v2."""

    path: str
    key: str | None = None
    version: int | None = None
    mount: str | None = None

    @classmethod
    def parse(cls, raw: str, default_mount: str | None = None) -> "SecretRef":
        """Converte a string ``raw`` em :class:`SecretRef`.

        :raises InvalidReferenceError: formato inválido ou caminho com ``..``.
        """
        if not isinstance(raw, str) or not raw.strip():
            raise InvalidReferenceError("referência vazia")
        m = _REF_RE.match(raw.strip())
        if not m:
            raise InvalidReferenceError(f"referência inválida: {raw!r}")
        path = m.group("path").strip("/")
        if not path or ".." in path.split("/"):
            raise InvalidReferenceError(f"caminho inválido: {raw!r}")
        version = m.group("version")
        return cls(
            path=path,
            key=m.group("key"),
            version=int(version) if version else None,
            mount=m.group("mount") or default_mount,
        )

    def with_mount(self, mount: str) -> "SecretRef":
        """Cópia da referência com o mount preenchido (se ainda não tiver)."""
        if self.mount:
            return self
        return SecretRef(self.path, self.key, self.version, mount)

    def cache_key(self) -> str:
        """Chave estável usada pelo componente de cache."""
        return f"{self.mount or ''}:{self.path}@{self.version or 'latest'}"

    def __str__(self) -> str:
        s = f"{self.mount + ':' if self.mount else ''}{self.path}"
        if self.key:
            s += f"#{self.key}"
        if self.version:
            s += f"@{self.version}"
        return s
