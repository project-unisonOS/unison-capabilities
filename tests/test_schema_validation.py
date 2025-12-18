from __future__ import annotations

import pytest

from schema import validate_manifest
from errors import CapabilityManifestError


def test_manifest_requires_fields() -> None:
    with pytest.raises(CapabilityManifestError):
        validate_manifest({"id": "x"})


def test_manifest_accepts_minimal_tool_manifest() -> None:
    m = {
        "id": "demo.echo",
        "type": "tool",
        "version": "0.1.0",
        "description": "Echo",
        "origin": {"source": "local", "digest": "sha256:" + "0" * 64, "path": "."},
        "interfaces": {"inputs": {"type": "object"}, "outputs": {"type": "object"}},
        "permissions": {"network": "deny", "filesystem": "none", "devices": []},
        "runtime": {"sandbox": "process", "resources": {"cpu": "default", "memory": "default"}},
        "trust_level": "local",
        "execution": {"channel": "programmatic"},
        "implementation": {"kind": "python", "python": {"callable": "capability_builtins:echo"}},
    }
    validate_manifest(m)

