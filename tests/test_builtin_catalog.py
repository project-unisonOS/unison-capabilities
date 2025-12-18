from __future__ import annotations

from pathlib import Path

from execution import ExecutionEngine
from policy import CapabilityPolicy
from resolver import CapabilityResolver
from store import CapabilityStore
from schema import validate_manifest


def test_resolve_from_builtin_catalog(tmp_path: Path) -> None:
    base = tmp_path / "manifest.base.json"
    m = {
        "id": "demo.echo",
        "type": "tool",
        "version": "0.1.0",
        "description": "Echo input text",
        "origin": {"source": "local", "digest": "sha256:" + "0" * 64, "path": "builtin"},
        "interfaces": {"inputs": {"type": "object"}, "outputs": {"type": "object"}},
        "permissions": {"network": "deny", "filesystem": "none", "devices": []},
        "runtime": {"sandbox": "process", "resources": {"cpu": "default", "memory": "default"}, "timeout_seconds": 5},
        "trust_level": "local",
        "enabled": True,
        "execution": {"channel": "programmatic"},
        "implementation": {"kind": "python", "python": {"callable": "capability_builtins:echo"}},
    }
    validate_manifest(m)
    base.write_text('{"capabilities": [' + __import__("json").dumps(m) + "]}\n", encoding="utf-8")

    r = CapabilityResolver(
        store=CapabilityStore(base_dir=tmp_path, base_catalog_path=base),
        policy=CapabilityPolicy(trust_allow={"local", "verified", "community"}),
        exec_engine=ExecutionEngine(),
        registries=[],
    )

    c = r.resolve(step={"intent": "demo.echo", "constraints": {}})
    assert c.manifest["id"] == "demo.echo"
