from __future__ import annotations

import json
from pathlib import Path

from schema import validate_manifest
from store import CapabilityRef, CapabilityStore


def _tool(capability_id: str, *, enabled: bool = True, desc: str = "d") -> dict:
    m = {
        "id": capability_id,
        "type": "tool",
        "version": "0.1.0",
        "description": desc,
        "origin": {"source": "local", "digest": "sha256:" + "0" * 64, "path": "."},
        "interfaces": {"inputs": {"type": "object"}, "outputs": {"type": "object"}},
        "permissions": {"network": "deny", "filesystem": "none", "devices": []},
        "runtime": {"sandbox": "process", "resources": {"cpu": "default", "memory": "default"}},
        "trust_level": "local",
        "enabled": enabled,
        "execution": {"channel": "programmatic"},
        "implementation": {"kind": "python", "python": {"callable": "capability_builtins:echo"}},
    }
    validate_manifest(m)
    return m


def test_merge_precedence_local_overrides_base(tmp_path: Path) -> None:
    base_path = tmp_path / "manifest.base.json"
    local_dir = tmp_path / "store"
    store = CapabilityStore(base_dir=local_dir, base_catalog_path=base_path)

    base_caps = [_tool("a", enabled=True, desc="base"), _tool("b", enabled=True, desc="base-b")]
    base_path.write_text(json.dumps({"capabilities": base_caps}) + "\n", encoding="utf-8")

    # Local overrides `a` and adds `c`.
    store.base_dir.mkdir(parents=True, exist_ok=True)
    local_caps = [_tool("a", enabled=False, desc="local"), _tool("c", enabled=True, desc="local-c")]
    store.local_catalog().write_text(json.dumps({"capabilities": local_caps}) + "\n", encoding="utf-8")

    merged = store.merged_catalog()
    assert merged["a"]["description"] == "local"
    assert merged["a"]["enabled"] is False
    assert merged["b"]["description"] == "base-b"
    assert merged["c"]["description"] == "local-c"


def test_writes_go_to_local_only(tmp_path: Path) -> None:
    base_path = tmp_path / "manifest.base.json"
    store = CapabilityStore(base_dir=tmp_path / "store", base_catalog_path=base_path)
    base_path.write_text(json.dumps({"capabilities": [_tool("a", enabled=True)]}) + "\n", encoding="utf-8")

    m2 = _tool("a", enabled=False)
    store.base_dir.mkdir(parents=True, exist_ok=True)
    store.upsert_local(m2)

    base_loaded = store.load_base_catalog()
    assert base_loaded["a"]["enabled"] is True
    local_loaded = store.load_local_catalog()
    assert local_loaded["a"]["enabled"] is False


def test_factory_reset_keeps_base(tmp_path: Path) -> None:
    base_path = tmp_path / "manifest.base.json"
    store = CapabilityStore(base_dir=tmp_path / "store", base_catalog_path=base_path)
    base_path.write_text(json.dumps({"capabilities": [_tool("a", enabled=True)]}) + "\n", encoding="utf-8")
    store.base_dir.mkdir(parents=True, exist_ok=True)

    store.upsert_local(_tool("b", enabled=False))
    store.put_manifest(manifest=_tool("b", enabled=False), meta={"installed_via": "unit"})
    payload_src = tmp_path / "payload_src"
    payload_src.mkdir()
    (payload_src / "SKILL.md").write_text("# demo\n", encoding="utf-8")
    store.put_payload_from_path(ref=CapabilityRef(capability_id="b", version="0.1.0"), src_path=str(payload_src))

    assert store.local_catalog().exists()
    assert (store.base_dir / "manifests").exists()
    assert (store.base_dir / "payloads").exists()

    store.factory_reset()
    assert store.local_catalog().exists() is False
    assert (store.base_dir / "manifests").exists() is False
    assert (store.base_dir / "payloads").exists() is False
    assert store.load_base_catalog()["a"]["id"] == "a"
