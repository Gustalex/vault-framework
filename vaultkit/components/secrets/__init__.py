"""Componente de Segredos.

Interface provida: :class:`ISecretStore`.
Interfaces requeridas: ``IVaultTransport`` e ``ITokenProvider``.
"""

from .interfaces import ISecretStore, Secret
from .kv2 import KVv2SecretStore

__all__ = ["ISecretStore", "Secret", "KVv2SecretStore"]
