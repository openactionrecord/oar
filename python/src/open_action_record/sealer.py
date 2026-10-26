"""Sealing: a separate service countersigns each record's payload digest with a sequence number, keeps a
hash-chained log and signs checkpoints over it. Run it separately, with its own key, so the writer of the records
cannot rewrite them alone. This in-process version is for tests and single-machine setups."""

from __future__ import annotations

import threading
from typing import Any, Callable, Protocol

from .canonical import digest
from .keys import SigningKey, public_keys, sign_canonical
from .times import iso_now


class SealingService(Protocol):
    def seal(self, payload_digest: str) -> dict[str, Any]: ...
    def keys(self) -> dict[str, Any]: ...
    def checkpoints(self) -> list[dict[str, Any]]: ...


def next_log_head(prev: str | None, seq: int, payload_digest: str, sealed_at: str) -> str:
    return digest({"prev": prev, "digest": payload_digest, "seq": seq, "sealed_at": sealed_at})


class LocalSealer:
    def __init__(self, key: SigningKey, *, checkpoint_every: int = 1, now: Callable[[], str] | None = None):
        self._key = key
        self._every = checkpoint_every
        self._now = now or iso_now
        self._seq = 0
        self._head: str | None = None
        self._last_checkpointed = 0
        self._checkpoints: list[dict[str, Any]] = []
        self._lock = threading.Lock()

    def seal(self, payload_digest: str) -> dict[str, Any]:
        with self._lock:
            self._seq += 1
            sealed_at = self._now()
            sig = sign_canonical({"digest": payload_digest, "seq": self._seq, "sealed_at": sealed_at}, self._key)
            self._head = next_log_head(self._head, self._seq, payload_digest, sealed_at)
            seal = {"sealer_kid": self._key.kid, "seq": self._seq, "sealed_at": sealed_at, "sig": sig}
            if self._seq - self._last_checkpointed >= self._every:
                self._checkpoint_locked()
            return seal

    def checkpoint(self) -> dict[str, Any] | None:
        with self._lock:
            return self._checkpoint_locked()

    def _checkpoint_locked(self) -> dict[str, Any] | None:
        if self._head is None:
            return None
        if self._last_checkpointed == self._seq:
            return self._checkpoints[-1]
        body = {"count": self._seq, "head_digest": self._head, "at": self._now()}
        cp = {**body, "sealer_kid": self._key.kid, "sig": sign_canonical(body, self._key)}
        self._checkpoints.append(cp)
        self._last_checkpointed = self._seq
        return cp

    def keys(self) -> dict[str, Any]:
        return public_keys(self._key)

    def checkpoints(self) -> list[dict[str, Any]]:
        with self._lock:
            return [dict(c) for c in self._checkpoints]
