"""Implementações do cache."""

from __future__ import annotations

import threading
import time
from collections import OrderedDict
from typing import Any, Callable

from .interfaces import ISecretCache


class TTLSecretCache(ISecretCache):
    """Cache LRU com expiração por tempo, seguro para múltiplas threads.

    :param ttl: tempo de vida padrão (segundos).
    :param max_entries: limite de entradas (a mais antiga sai primeiro).
    :param clock: relógio injetável (os testes usam um relógio falso).
    """

    def __init__(self, ttl: float = 60.0, max_entries: int = 1024, clock: Callable[[], float] = time.monotonic):
        self.ttl = ttl
        self.max_entries = max_entries
        self._clock = clock
        self._data: OrderedDict[str, tuple[float, Any]] = OrderedDict()
        self._lock = threading.Lock()
        self._hits = 0
        self._misses = 0

    def get(self, key: str) -> Any | None:
        with self._lock:
            item = self._data.get(key)
            if item is None or item[0] <= self._clock():
                if item is not None:
                    del self._data[key]
                self._misses += 1
                return None
            self._data.move_to_end(key)
            self._hits += 1
            return item[1]

    def put(self, key: str, value: Any, ttl: float | None = None) -> None:
        ttl = self.ttl if ttl is None else ttl
        if ttl <= 0:
            return
        with self._lock:
            self._data[key] = (self._clock() + ttl, value)
            self._data.move_to_end(key)
            while len(self._data) > self.max_entries:
                self._data.popitem(last=False)

    def invalidate(self, key: str | None = None) -> None:
        with self._lock:
            if key is None:
                self._data.clear()
            else:
                self._data.pop(key, None)

    def stats(self) -> dict[str, int]:
        with self._lock:
            return {"hits": self._hits, "misses": self._misses, "size": len(self._data)}


class NullCache(ISecretCache):
    """Cache desligado (Null Object): sempre busca no cofre."""

    def get(self, key: str) -> Any | None:
        return None

    def put(self, key: str, value: Any, ttl: float | None = None) -> None:
        return None

    def invalidate(self, key: str | None = None) -> None:
        return None

    def stats(self) -> dict[str, int]:
        return {"hits": 0, "misses": 0, "size": 0}
