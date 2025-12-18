from __future__ import annotations

import threading
from pathlib import Path

import pytest

from errors import CapabilityInstallError
from execution import ExecutionEngine
from installer import Installer
from locks import FileLock
from policy import CapabilityPolicy
from resolver import CapabilityResolver
from schema import validate_manifest
from store import CapabilityStore


def _manifest() -> dict:
    return {
        "id": "demo.echo",
        "type": "tool",
        "version": "0.1.0",
        "description": "Echo input text",
        "origin": {"source": "local", "digest": "sha256:" + "0" * 64, "path": "."},
        "interfaces": {"inputs": {"type": "object"}, "outputs": {"type": "object"}},
        "permissions": {"network": "deny", "filesystem": "none", "devices": []},
        "runtime": {"sandbox": "process", "resources": {"cpu": "default", "memory": "default"}, "timeout_seconds": 5},
        "trust_level": "local",
        "execution": {"channel": "programmatic"},
        "implementation": {"kind": "python", "python": {"callable": "capability_builtins:echo"}},
    }


def test_install_promote_failure_rolls_back(tmp_path: Path) -> None:
    store = CapabilityStore(base_dir=tmp_path / "store")
    store.base_dir.mkdir(parents=True, exist_ok=True)

    # Force a failure during promote by blocking creation of the final parent dir.
    (store.base_dir / "manifests" / "demo.echo").parent.mkdir(parents=True, exist_ok=True)
    (store.base_dir / "manifests" / "demo.echo").write_text("not a dir", encoding="utf-8")

    m = _manifest()
    validate_manifest(m)
    installer = Installer(store=store)

    with pytest.raises(CapabilityInstallError):
        installer.install_manifest_atomic(manifest=m, meta={"installed_via": "unit"})

    assert not (store.base_dir / "manifests" / "demo.echo" / "0.1.0").is_dir()
    staging = store.base_dir / "tmp" / "staging"
    if staging.exists():
        assert list(staging.glob("**/*")) == []


def test_concurrent_installs_are_safe(tmp_path: Path) -> None:
    store = CapabilityStore(base_dir=tmp_path / "store")
    policy = CapabilityPolicy(trust_allow={"local", "verified", "community"})
    lock = FileLock(store.lock_path())
    r = CapabilityResolver(store=store, policy=policy, exec_engine=ExecutionEngine(), registries=[], lock=lock)

    m = _manifest()
    validate_manifest(m)

    barrier = threading.Barrier(8)
    errs: list[Exception] = []

    def _worker() -> None:
        try:
            barrier.wait(timeout=5)
            r.install(candidate={"source": "unit", "manifest": m})
            # Read while others may still be installing.
            r.get(capability_id="demo.echo", version="0.1.0")
        except Exception as exc:
            errs.append(exc)

    threads = [threading.Thread(target=_worker, daemon=True) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join(timeout=10)

    assert errs == []
    assert (store.base_dir / "manifests" / "demo.echo" / "0.1.0" / "capability.manifest.json").exists()
