from __future__ import annotations

import json
import os
import shutil
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Iterable, Optional, Tuple

from errors import CapabilityManifestError, CapabilityNotFoundError
from atomic import atomic_write_json
from schema import validate_manifest


_MANIFEST_FILENAME = "capability.manifest.json"
_META_FILENAME = "install.meta.json"
_LOCAL_CATALOG_FILENAME = "manifest.local.json"
_CATALOG_VERSION = "catalog.v1"


def _safe_dirname(value: str) -> str:
    if not value or value.strip() != value:
        raise CapabilityManifestError("invalid id/version for storage")
    if any(x in value for x in ("/", "\\", "..", "\x00")):
        raise CapabilityManifestError("unsafe id/version for storage")
    return value


@dataclass(frozen=True)
class CapabilityRef:
    capability_id: str
    version: str


@dataclass(frozen=True)
class CapabilityStore:
    base_dir: Path
    base_catalog_path: Optional[Path] = None

    @classmethod
    def from_env(cls) -> "CapabilityStore":
        base = os.getenv("UNISON_CAPABILITY_STORE_DIR", "/var/lib/unison/capabilities")
        return cls(base_dir=Path(base).expanduser().resolve())

    def _repo_root(self) -> Path:
        return Path(__file__).resolve().parents[1]

    def base_catalog(self) -> Path:
        if self.base_catalog_path:
            return self.base_catalog_path
        return self._repo_root() / "manifests" / "manifest.base.json"

    def local_catalog(self) -> Path:
        return self.base_dir / _LOCAL_CATALOG_FILENAME

    def _manifests_dir(self) -> Path:
        return self.base_dir / "manifests"

    def _payloads_dir(self) -> Path:
        return self.base_dir / "payloads"

    def _tmp_dir(self) -> Path:
        return self.base_dir / "tmp"

    def _locks_dir(self) -> Path:
        return self.base_dir / "locks"

    def _install_dir(self, ref: CapabilityRef) -> Path:
        return self._manifests_dir() / _safe_dirname(ref.capability_id) / _safe_dirname(ref.version)

    def _payload_dir(self, ref: CapabilityRef) -> Path:
        return self._payloads_dir() / _safe_dirname(ref.capability_id) / _safe_dirname(ref.version)

    def _manifest_path(self, ref: CapabilityRef) -> Path:
        return self._install_dir(ref) / _MANIFEST_FILENAME

    def _meta_path(self, ref: CapabilityRef) -> Path:
        return self._install_dir(ref) / _META_FILENAME

    def lock_path(self) -> Path:
        return self._locks_dir() / "store.lock"

    def list_installed(self) -> list[CapabilityRef]:
        """
        Local install inventory (on-disk artifacts).

        NOTE: The effective resolver view is driven by base+local catalogs; this is
        used for cleanup/reset and to prevent partial installs from being treated
        as installed until promoted.
        """
        out: list[CapabilityRef] = []
        root = self._manifests_dir()
        if not root.exists():
            return out
        for id_dir in root.iterdir():
            if not id_dir.is_dir():
                continue
            for ver_dir in id_dir.iterdir():
                if (ver_dir / _MANIFEST_FILENAME).exists():
                    out.append(CapabilityRef(capability_id=id_dir.name, version=ver_dir.name))
        out.sort(key=lambda r: (r.capability_id, r.version))
        return out

    def get_manifest(self, ref: CapabilityRef) -> Dict[str, Any]:
        path = self._manifest_path(ref)
        if not path.exists():
            raise CapabilityNotFoundError(f"capability not installed: {ref.capability_id}@{ref.version}")
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise CapabilityManifestError(f"invalid installed manifest: {path}: {exc}") from exc
        if not isinstance(data, dict):
            raise CapabilityManifestError(f"invalid installed manifest root: {path}")
        return data

    def _load_catalog_file(self, path: Path) -> Dict[str, Dict[str, Any]]:
        if not path.exists():
            return {}
        try:
            raw = json.loads(path.read_text(encoding="utf-8"))
        except Exception as exc:
            raise CapabilityManifestError(f"invalid catalog json: {path}: {exc}") from exc
        if not isinstance(raw, dict):
            raise CapabilityManifestError(f"invalid catalog root: {path}")
        caps = raw.get("capabilities")
        if caps is None:
            # Allow bare list for convenience.
            caps = raw if isinstance(raw, list) else []
        if not isinstance(caps, list):
            raise CapabilityManifestError(f"invalid catalog capabilities list: {path}")
        out: Dict[str, Dict[str, Any]] = {}
        for item in caps:
            if not isinstance(item, dict):
                continue
            validate_manifest(item)
            cid = str(item.get("id") or "")
            if not cid:
                continue
            out[cid] = item
        return out

    def _write_local_catalog(self, items_by_id: Dict[str, Dict[str, Any]]) -> None:
        payload = {
            "catalog_version": _CATALOG_VERSION,
            "capabilities": list(items_by_id.values()),
        }
        atomic_write_json(self.local_catalog(), payload, mode=0o600)

    def load_base_catalog(self) -> Dict[str, Dict[str, Any]]:
        return self._load_catalog_file(self.base_catalog())

    def load_local_catalog(self) -> Dict[str, Dict[str, Any]]:
        return self._load_catalog_file(self.local_catalog())

    def merged_catalog(self) -> Dict[str, Dict[str, Any]]:
        base = self.load_base_catalog()
        local = self.load_local_catalog()
        merged = dict(base)
        merged.update(local)
        return merged

    def upsert_local(self, manifest: Dict[str, Any]) -> None:
        validate_manifest(manifest)
        cid = str(manifest.get("id") or "")
        if not cid:
            raise CapabilityManifestError("manifest.id required")
        local = self.load_local_catalog()
        local[cid] = manifest
        self._write_local_catalog(local)

    def delete_local(self, *, capability_id: str) -> bool:
        local = self.load_local_catalog()
        if capability_id not in local:
            return False
        local.pop(capability_id, None)
        self._write_local_catalog(local)
        return True

    def set_local_enabled(self, *, capability_id: str, enabled: bool) -> None:
        merged = self.merged_catalog()
        if capability_id not in merged:
            raise CapabilityNotFoundError(f"capability not found: {capability_id}")
        current = dict(merged[capability_id])
        current["enabled"] = bool(enabled)
        self.upsert_local(current)

    def factory_reset(self) -> None:
        """
        Delete local catalog + local installed artifacts (manifests/payloads/tmp),
        while keeping the shipped base catalog intact.
        """
        self.local_catalog().unlink(missing_ok=True)
        shutil.rmtree(self._manifests_dir(), ignore_errors=True)
        shutil.rmtree(self._payloads_dir(), ignore_errors=True)
        shutil.rmtree(self._tmp_dir(), ignore_errors=True)

    def put_manifest(self, *, manifest: Dict[str, Any], meta: Optional[Dict[str, Any]] = None) -> CapabilityRef:
        cap_id = str(manifest.get("id"))
        ver = str(manifest.get("version"))
        ref = CapabilityRef(capability_id=cap_id, version=ver)
        target_dir = self._install_dir(ref)
        target_dir.mkdir(parents=True, exist_ok=True)
        atomic_write_json(self._manifest_path(ref), manifest, mode=0o600)
        meta_out = {"installed_at": time.time()}
        if isinstance(meta, dict):
            meta_out.update(meta)
        atomic_write_json(self._meta_path(ref), meta_out, mode=0o600)
        return ref

    def put_payload_from_path(self, *, ref: CapabilityRef, src_path: str) -> Path:
        src = Path(src_path).expanduser().resolve()
        if not src.exists():
            raise CapabilityManifestError(f"origin.path does not exist: {src}")
        target = self._payload_dir(ref)
        if target.exists():
            shutil.rmtree(target)
        target.parent.mkdir(parents=True, exist_ok=True)
        if src.is_dir():
            shutil.copytree(src, target)
        else:
            target.mkdir(parents=True, exist_ok=True)
            shutil.copy2(src, target / src.name)
        return target

    def remove(self, ref: CapabilityRef) -> bool:
        path = self._install_dir(ref)
        if not path.exists():
            removed_manifest = False
        else:
            removed_manifest = True
            for p in sorted(path.glob("**/*"), reverse=True):
                if p.is_file():
                    p.unlink(missing_ok=True)
                elif p.is_dir():
                    try:
                        p.rmdir()
                    except OSError:
                        pass
            try:
                path.rmdir()
            except OSError:
                pass
            # Attempt to remove empty parent dirs
            parent = path.parent
            try:
                parent.rmdir()
            except OSError:
                pass
        payload = self._payload_dir(ref)
        if payload.exists():
            shutil.rmtree(payload, ignore_errors=True)
            try:
                payload.parent.rmdir()
            except OSError:
                pass
        return removed_manifest
