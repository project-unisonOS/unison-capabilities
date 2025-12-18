from __future__ import annotations

import base64
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional, Protocol

from cryptography.fernet import Fernet, InvalidToken

from atomic import atomic_write_json
from errors import CapabilityPolicyError
from locks import FileLock


def _is_truthy(v: str | None) -> bool:
    return (v or "").strip().lower() in {"1", "true", "yes", "on"}


class SecretsBackend(Protocol):
    def put(self, *, handle: str, value: Dict[str, Any]) -> None: ...
    def get(self, *, handle: str) -> Dict[str, Any]: ...
    def delete(self, *, handle: str) -> bool: ...


def _ensure_handle(handle: str) -> None:
    if not isinstance(handle, str) or not handle.startswith("secret://"):
        raise CapabilityPolicyError("invalid secret handle")


def _load_fernet_key() -> bytes:
    key = os.getenv("UNISON_CAPABILITY_SECRETS_KEY")
    if key:
        return key.encode("utf-8")
    key_file = os.getenv("UNISON_CAPABILITY_SECRETS_KEY_FILE")
    if key_file and Path(key_file).exists():
        return Path(key_file).read_text(encoding="utf-8").strip().encode("utf-8")
    if _is_truthy(os.getenv("UNISON_CAPABILITY_SECRETS_DEV_AUTOGEN")):
        return Fernet.generate_key()
    raise CapabilityPolicyError("secrets backend not configured (missing UNISON_CAPABILITY_SECRETS_KEY)")


@dataclass(frozen=True)
class FileFernetSecretsBackend:
    path: Path
    _fernet: Fernet
    _lock: FileLock

    @classmethod
    def from_env(cls, *, base_dir: Path) -> "FileFernetSecretsBackend":
        p = base_dir / "secrets.enc.json"
        key = _load_fernet_key()
        lock = FileLock(base_dir / "locks" / "secrets.lock")
        return cls(path=p, _fernet=Fernet(key), _lock=lock)

    def _read_all(self) -> Dict[str, Dict[str, Any]]:
        if not self.path.exists():
            return {}
        raw = json.loads(self.path.read_text(encoding="utf-8"))
        if not isinstance(raw, dict) or "data" not in raw:
            raise CapabilityPolicyError("invalid secrets store")
        token = str(raw.get("data") or "")
        try:
            pt = self._fernet.decrypt(token.encode("utf-8"))
        except InvalidToken as exc:
            raise CapabilityPolicyError("unable to decrypt secrets store") from exc
        data = json.loads(pt.decode("utf-8"))
        if not isinstance(data, dict):
            raise CapabilityPolicyError("invalid secrets store plaintext")
        out: Dict[str, Dict[str, Any]] = {}
        for k, v in data.items():
            if isinstance(k, str) and isinstance(v, dict):
                out[k] = v
        return out

    def _write_all(self, data: Dict[str, Dict[str, Any]]) -> None:
        pt = json.dumps(data, sort_keys=True, separators=(",", ":")).encode("utf-8")
        token = self._fernet.encrypt(pt).decode("utf-8")
        atomic_write_json(self.path, {"v": 1, "data": token}, mode=0o600)

    def put(self, *, handle: str, value: Dict[str, Any]) -> None:
        _ensure_handle(handle)
        if not isinstance(value, dict):
            raise CapabilityPolicyError("secret value must be an object")
        with self._lock.exclusive():
            data = self._read_all()
            data[handle] = value
            self._write_all(data)

    def get(self, *, handle: str) -> Dict[str, Any]:
        _ensure_handle(handle)
        with self._lock.shared():
            data = self._read_all()
            if handle not in data:
                raise CapabilityPolicyError("secret handle not found")
            return data[handle]

    def delete(self, *, handle: str) -> bool:
        _ensure_handle(handle)
        with self._lock.exclusive():
            data = self._read_all()
            if handle not in data:
                return False
            data.pop(handle, None)
            self._write_all(data)
            return True
