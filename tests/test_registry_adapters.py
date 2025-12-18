from __future__ import annotations

import json
from pathlib import Path

from discovery import StaticCatalogAdapter
from execution import ExecutionEngine
from policy import CapabilityPolicy
from resolver import CapabilityResolver
from schema import validate_manifest
from store import CapabilityStore


def _tool(capability_id: str, desc: str, trust: str = "local") -> dict:
    m = {
        "id": capability_id,
        "type": "tool",
        "version": "0.1.0",
        "description": desc,
        "origin": {"source": "local", "digest": "sha256:" + "0" * 64, "path": "seed"},
        "interfaces": {"inputs": {"type": "object"}, "outputs": {"type": "object"}},
        "permissions": {"network": "deny", "filesystem": "none", "devices": []},
        "runtime": {"sandbox": "process", "resources": {"cpu": "default", "memory": "default"}, "timeout_seconds": 5},
        "trust_level": trust,
        "enabled": True,
        "execution": {"channel": "programmatic"},
        "implementation": {"kind": "python", "python": {"callable": "capability_builtins:echo"}},
    }
    validate_manifest(m)
    return m


def test_local_catalog_preferred_over_registry(tmp_path: Path) -> None:
    base = tmp_path / "manifest.base.json"
    base.write_text(json.dumps({"capabilities": [_tool("echo.local", "echo local")]}), encoding="utf-8")

    static = tmp_path / "static.json"
    static.write_text(json.dumps({"capabilities": [_tool("echo.remote", "echo remote", trust="community")]}), encoding="utf-8")

    store = CapabilityStore(base_dir=tmp_path / "store", base_catalog_path=base)
    r = CapabilityResolver(
        store=store,
        policy=CapabilityPolicy(trust_allow={"local", "verified", "community"}),
        exec_engine=ExecutionEngine(),
        registries=[StaticCatalogAdapter(name="static", catalog_path=str(static))],
    )

    results = r.search(intent="echo", constraints={})
    assert results[0].manifest["id"] == "echo.local"


def test_registry_suggested_when_missing(tmp_path: Path) -> None:
    base = tmp_path / "manifest.base.json"
    base.write_text(json.dumps({"capabilities": []}), encoding="utf-8")

    static = tmp_path / "static.json"
    static.write_text(json.dumps({"capabilities": [_tool("weather.summary", "weather summary", trust="community")]}), encoding="utf-8")

    store = CapabilityStore(base_dir=tmp_path / "store", base_catalog_path=base)
    r = CapabilityResolver(
        store=store,
        policy=CapabilityPolicy(trust_allow={"local", "verified", "community"}),
        exec_engine=ExecutionEngine(),
        registries=[StaticCatalogAdapter(name="static", catalog_path=str(static))],
    )

    results = r.search(intent="weather", constraints={})
    assert any(c.manifest["id"] == "weather.summary" for c in results)

