from __future__ import annotations

import json
from pathlib import Path

import pytest

from errors import CapabilityNotFoundError, CapabilityPolicyError
from execution import ExecutionEngine
from policy import CapabilityPolicy
from resolver import CapabilityResolver
from schema import validate_manifest
from store import CapabilityStore


def _demo_manifest(trust: str = "local") -> dict:
    return {
        "id": "demo.echo",
        "type": "tool",
        "version": "0.1.0",
        "description": "Echo input text",
        "origin": {"source": "local", "digest": "sha256:" + "0" * 64, "path": "."},
        "interfaces": {"inputs": {"type": "object"}, "outputs": {"type": "object"}},
        "permissions": {"network": "deny", "filesystem": "none", "devices": []},
        "runtime": {"sandbox": "process", "resources": {"cpu": "default", "memory": "default"}, "timeout_seconds": 5},
        "trust_level": trust,
        "execution": {"channel": "programmatic"},
        "implementation": {"kind": "python", "python": {"callable": "capability_builtins:echo"}},
    }


def test_install_list_get_run_remove(tmp_path: Path) -> None:
    store = CapabilityStore(base_dir=tmp_path)
    policy = CapabilityPolicy(trust_allow={"local"})
    r = CapabilityResolver(store=store, policy=policy, exec_engine=ExecutionEngine(), registries=[])

    m = _demo_manifest()
    validate_manifest(m)

    r.install(candidate={"source": "unit", "manifest": m})
    items = r.list()
    assert any(x["id"] == "demo.echo" for x in items)

    got = r.get(capability_id="demo.echo", version="0.1.0")
    assert got["id"] == "demo.echo"

    out = r.run(capability_id="demo.echo", args={"text": "hi"})
    assert out["echo"] == "hi"

    removed = r.remove(capability_id="demo.echo", version="0.1.0")
    assert removed is True
    with pytest.raises(CapabilityNotFoundError):
        r.get(capability_id="demo.echo", version="0.1.0")


def test_policy_blocks_untrusted(tmp_path: Path) -> None:
    store = CapabilityStore(base_dir=tmp_path)
    policy = CapabilityPolicy(trust_allow={"local"})
    r = CapabilityResolver(store=store, policy=policy, exec_engine=ExecutionEngine(), registries=[])

    m = _demo_manifest(trust="untrusted")
    validate_manifest(m)
    with pytest.raises(CapabilityPolicyError):
        r.install(candidate={"source": "unit", "manifest": m})


def test_install_copies_local_payload(tmp_path: Path) -> None:
    payload = tmp_path / "pack"
    payload.mkdir()
    (payload / "SKILL.md").write_text("# Demo skill pack\n", encoding="utf-8")

    store = CapabilityStore(base_dir=tmp_path / "store")
    policy = CapabilityPolicy(trust_allow={"local"})
    r = CapabilityResolver(store=store, policy=policy, exec_engine=ExecutionEngine(), registries=[])

    m = _demo_manifest()
    m["origin"] = {"source": "local", "digest": "sha256:" + "0" * 64, "path": str(payload)}
    validate_manifest(m)
    r.install(candidate={"source": "unit", "manifest": m})

    copied = (store.base_dir / "payloads" / "demo.echo" / "0.1.0" / "SKILL.md")
    assert copied.exists()
