"""Classe central do framework: **Template Method** com *hotspots*.

O método :meth:`SecretAccessFramework.execute` é o **frozen spot** — o algoritmo
fixo que toda aplicação reaproveita (autenticar, consultar cache, buscar no cofre,
auditar, mascarar, tratar erros e liberar recursos). As aplicações só preenchem
os **hotspots** (pontos de adaptação):

=========================  ==============  =======================================
Hotspot                    Tipo            Para que serve
=========================  ==============  =======================================
``load_references``        abstrato        de onde vêm as referências (arquivo,
                                           banco, CLI...) → ``{alias: referência}``
``transform``              abstrato        converte o :class:`Secret` no objeto que
                                           a aplicação usa (credencial, variável...)
``consume``                abstrato        o que a aplicação faz com os segredos
``parse_reference``        hook            sintaxe própria de referência
``validate_reference``     hook            regras extras (ex.: só ``apps/x/*``)
``on_error``               hook            tratamento de falha (padrão: relançar)
``before_run``/``after_run``  hook         preparação e limpeza
``create_provider``        factory method  qual cofre/estratégia usar
``create_cache``           factory method  política de cache
``create_audit_sink``      factory method  para onde vai a auditoria
=========================  ==============  =======================================
"""

from __future__ import annotations

import logging
import time
from abc import ABC, abstractmethod
from typing import Any, Generic, Mapping, TypeVar

from .components.audit import AuditEvent, IAuditSink, LoggingAuditSink
from .components.cache import ISecretCache, TTLSecretCache
from .components.secrets import Secret
from .config import VaultConfig
from .errors import PermissionDeniedError, VaultKitError
from .providers import SecretProvider, get_provider
from .reference import SecretRef

T = TypeVar("T")
R = TypeVar("R")

log = logging.getLogger("vaultkit.framework")


class SecretAccessFramework(ABC, Generic[T, R]):
    """Esqueleto reutilizável de uma aplicação que consome segredos do cofre.

    :param config: configuração; ``None`` lê de ``VAULTKIT_*``.
    :param provider: injeta um provider pronto (testes); senão usa :meth:`create_provider`.
    :param cache: injeta um cache; senão usa :meth:`create_cache`.
    :param audit: injeta um audit sink; senão usa :meth:`create_audit_sink`.
    """

    app_name: str = "vaultkit-app"

    def __init__(self, config: VaultConfig | None = None, *, provider: SecretProvider | None = None,
                 cache: ISecretCache | None = None, audit: IAuditSink | None = None):
        self.config = config or VaultConfig.from_env()
        self._provider = provider
        self.cache = cache if cache is not None else self.create_cache()
        self.audit = audit if audit is not None else self.create_audit_sink()

    @property
    def provider(self) -> SecretProvider:
        """Provider criado sob demanda (só conecta quando precisa)."""
        if self._provider is None:
            self._provider = self.create_provider()
        return self._provider

    # ================================================================== #
    # TEMPLATE METHOD (frozen spot)
    # ================================================================== #
    def execute(self) -> R:
        """Algoritmo fixo do framework.

        1. ``before_run()``                          — hook
        2. ``load_references()``                     — **hotspot**
        3. para cada referência:
              ``parse_reference()``                  — hook
              ``validate_reference()``               — hook
              ``_resolve()``  cache → cofre → auditoria  (fixo)
              ``transform()``                        — **hotspot**
        4. ``consume(itens)``                        — **hotspot**
        5. ``on_success()`` / ``on_error()``         — hooks
        6. ``after_run()`` e liberação do provider   — hook + fixo
        """
        try:
            self.before_run()
            items: dict[str, T] = {}
            for alias, raw in self.load_references().items():
                ref = self.parse_reference(raw).with_mount(self.config.kv_mount)
                self.validate_reference(alias, ref)
                secret = self._resolve(alias, ref)
                items[alias] = self.transform(alias, ref, secret)
            result = self.consume(items)
            self.on_success(result)
            return result
        except VaultKitError as exc:
            return self.on_error(exc)
        finally:
            try:
                self.after_run()
            finally:
                self.release()

    # ------------------------------------------------------------------ #
    # Passos fixos (frozen spots)
    # ------------------------------------------------------------------ #
    def _resolve(self, alias: str, ref: SecretRef) -> Secret:
        """Cache → provider → auditoria. Igual para toda aplicação."""
        key = ref.cache_key()
        cached = self.cache.get(key)
        if cached is not None:
            self._audit("secret.read", ref, "cache_hit", 0.0, alias)
            return cached
        start = time.perf_counter()
        try:
            secret = self.provider.get_secret(ref)
        except PermissionDeniedError:
            self._audit("secret.read", ref, "denied", self._ms(start), alias)
            raise
        except VaultKitError as exc:
            self._audit("secret.read", ref, "error", self._ms(start), alias, error=type(exc).__name__)
            raise
        self.cache.put(key, secret, self.config.cache_ttl)
        self._audit("secret.read", ref, "success", self._ms(start), alias, version=secret.version)
        return secret

    def _audit(self, action: str, ref: SecretRef, outcome: str, latency: float, alias: str, **detail: Any) -> None:
        self.audit.record(AuditEvent(
            action=action, resource=f"{ref.mount}:{ref.path}", outcome=outcome, actor=self.app_name,
            service=f"app:{self.app_name}", latency_ms=round(latency, 2),
            detail={"alias": alias, "key": ref.key, "provider": self.provider.name, **detail},
        ))

    @staticmethod
    def _ms(start: float) -> float:
        return (time.perf_counter() - start) * 1000

    def release(self) -> None:
        """Fecha o provider (revoga o token) ao fim da execução."""
        if self._provider is not None:
            self._provider.close()
            self._provider = None

    def read(self, raw: str) -> Any:
        """Atalho para ler um valor isolado reaproveitando cache e auditoria."""
        ref = self.parse_reference(raw).with_mount(self.config.kv_mount)
        return self._resolve(raw, ref).value(ref.key)

    # ================================================================== #
    # HOTSPOTS abstratos — toda aplicação implementa
    # ================================================================== #
    @abstractmethod
    def load_references(self) -> Mapping[str, str]:
        """Devolve ``{alias: referência}`` com os segredos que a aplicação precisa."""

    @abstractmethod
    def transform(self, alias: str, ref: SecretRef, secret: Secret) -> T:
        """Converte o segredo lido no objeto de domínio da aplicação."""

    @abstractmethod
    def consume(self, items: dict[str, T]) -> R:
        """Usa os objetos produzidos por :meth:`transform` e devolve o resultado."""

    # ================================================================== #
    # HOTSPOTS opcionais (hooks com comportamento padrão)
    # ================================================================== #
    def parse_reference(self, raw: str) -> SecretRef:
        """Converte a string em :class:`SecretRef` (padrão: ``[mount:]caminho[#chave][@versão]``)."""
        return SecretRef.parse(raw)

    def validate_reference(self, alias: str, ref: SecretRef) -> None:
        """Regras extras de validação. Padrão: aceita tudo."""

    def before_run(self) -> None:
        """Executado antes de carregar as referências."""

    def after_run(self) -> None:
        """Executado sempre ao final (sucesso ou erro)."""

    def on_success(self, result: R) -> None:
        """Executado quando ``consume`` termina sem erro."""

    def on_error(self, error: VaultKitError) -> R:
        """Tratamento de falha. Padrão: relança o erro."""
        raise error

    # ------------------------------------------------------------------ #
    # Factory methods (hotspots de criação)
    # ------------------------------------------------------------------ #
    def create_provider(self) -> SecretProvider:
        """Escolhe o cofre pela configuração (``openbao``, ``vault``, ``gateway``...)."""
        return get_provider(self.config)

    def create_cache(self) -> ISecretCache:
        """Política de cache. Padrão: TTL de ``config.cache_ttl`` segundos."""
        return TTLSecretCache(ttl=self.config.cache_ttl)

    def create_audit_sink(self) -> IAuditSink:
        """Para onde vai a auditoria. Padrão: ``logging``."""
        return LoggingAuditSink()


__all__ = ["SecretAccessFramework"]
