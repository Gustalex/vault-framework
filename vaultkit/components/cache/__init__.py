"""Componente de Cache.

Interface provida: :class:`ISecretCache`. Sem interfaces requeridas.
"""

from .interfaces import ISecretCache
from .ttl import NullCache, TTLSecretCache

__all__ = ["ISecretCache", "TTLSecretCache", "NullCache"]
