from __future__ import annotations

import json
import os
import shutil
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional

from atomic import atomic_write_json
from errors import CapabilityInstallError
from store import CapabilityRef, CapabilityStore


@dataclass(frozen=True)
class InstallResult:
    ref: CapabilityRef
    updated: bool


def _fsync_dir(path: Path) -> None:
    fd = os.open(str(path), os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


@dataclass(frozen=True)
class Installer:
    store: CapabilityStore

    def _stage_root(self) -> Path:
        root = self.store.base_dir / "tmp" / "staging"
        root.mkdir(parents=True, exist_ok=True)
        return root

    def _stage_dir(self, ref: CapabilityRef) -> Path:
        token = uuid.uuid4().hex
        return self._stage_root() / f"{ref.capability_id}@{ref.version}.{token}"

    def install_manifest_atomic(self, *, manifest: Dict[str, Any], meta: Optional[Dict[str, Any]] = None) -> InstallResult:
        cap_id = str(manifest.get("id") or "")
        ver = str(manifest.get("version") or "")
        if not cap_id or not ver:
            raise CapabilityInstallError("manifest must include id and version")
        ref = CapabilityRef(capability_id=cap_id, version=ver)

        final_dir = self.store._install_dir(ref)  # type: ignore[attr-defined]
        final_manifest = self.store._manifest_path(ref)  # type: ignore[attr-defined]
        final_meta = self.store._meta_path(ref)  # type: ignore[attr-defined]

        if final_manifest.exists():
            return InstallResult(ref=ref, updated=False)

        stage = self._stage_dir(ref)
        try:
            stage.mkdir(parents=True, exist_ok=False)
            stage_manifest_dir = stage / "manifests" / ref.capability_id / ref.version
            stage_manifest_dir.mkdir(parents=True, exist_ok=True)

            atomic_write_json(stage_manifest_dir / final_manifest.name, manifest, mode=0o600)
            meta_out = {"installed_via": (meta or {}).get("installed_via")} if isinstance(meta, dict) else {}
            atomic_write_json(stage_manifest_dir / final_meta.name, meta_out, mode=0o600)

            # Promote: rename staged dir into final location atomically.
            final_dir.parent.mkdir(parents=True, exist_ok=True)
            _fsync_dir(final_dir.parent)
            try:
                os.replace(stage_manifest_dir, final_dir)
            except OSError as exc:
                # Treat concurrent installs as success.
                if exc.errno in {17, 39}:  # EEXIST, ENOTEMPTY
                    return InstallResult(ref=ref, updated=False)
                raise
            _fsync_dir(final_dir.parent)
            return InstallResult(ref=ref, updated=True)
        except Exception as exc:
            raise CapabilityInstallError(f"install failed: {exc}") from exc
        finally:
            shutil.rmtree(stage, ignore_errors=True)
