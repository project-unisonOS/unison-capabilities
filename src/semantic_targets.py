from __future__ import annotations

import hashlib
import hmac
import json
import time
from dataclasses import dataclass
from typing import Callable


class TargetBindingError(PermissionError):
    pass


@dataclass(frozen=True)
class TargetBinding:
    capability: str
    target_id: str
    person_id: str
    state_version: str
    expires_at: int
    authority_token: str


class SemanticTargetAuthority:
    """Binds observed targets to a person, capability, state, and short lifetime."""

    def __init__(self, secret: bytes, clock: Callable[[], float] = time.time):
        if len(secret) < 32:
            raise ValueError("target authority secret must contain at least 32 bytes")
        self._secret = secret
        self._clock = clock

    def _signature(self, payload: dict[str, object]) -> str:
        encoded = json.dumps(payload, sort_keys=True, separators=(",", ":")).encode()
        return hmac.new(self._secret, encoded, hashlib.sha256).hexdigest()

    def bind(self, *, capability: str, target_id: str, person_id: str, state_version: str, ttl_seconds: int = 60) -> TargetBinding:
        expires_at = int(self._clock()) + ttl_seconds
        payload = {"capability": capability, "target_id": target_id, "person_id": person_id, "state_version": state_version, "expires_at": expires_at}
        return TargetBinding(**payload, authority_token=self._signature(payload))

    def authorize(self, binding: TargetBinding, *, capability: str, person_id: str, current_state_version: str) -> None:
        payload = {"capability": binding.capability, "target_id": binding.target_id, "person_id": binding.person_id, "state_version": binding.state_version, "expires_at": binding.expires_at}
        if not hmac.compare_digest(binding.authority_token, self._signature(payload)):
            raise TargetBindingError("target binding signature is invalid")
        if binding.expires_at <= int(self._clock()):
            raise TargetBindingError("target binding expired; observe the target again")
        if binding.person_id != person_id or binding.capability != capability:
            raise TargetBindingError("target authority does not match the person or capability")
        if binding.state_version != current_state_version:
            raise TargetBindingError("target state changed; observe the target again")
