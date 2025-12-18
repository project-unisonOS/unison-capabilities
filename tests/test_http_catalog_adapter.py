from __future__ import annotations

import httpx
from config import EgressConfig
from discovery import HttpCatalogAdapter
from egress import EgressController
from schema import validate_manifest


def test_http_catalog_requires_https() -> None:
    egress = EgressController(EgressConfig(allowlist=["https://x"], denylist=[], allow_private_networks=False))
    adapter = HttpCatalogAdapter(name="http", catalog_urls=["http://insecure.example/catalog.json"], egress=egress)
    try:
        adapter.list(query="x", filters=None)
        assert False, "expected exception"
    except ValueError:
        pass


def test_http_catalog_fetches_candidates_with_egress_allowlist() -> None:
    manifest = {
        "id": "catalog.tool",
        "type": "tool",
        "version": "0.1.0",
        "description": "Catalog tool",
        "origin": {"source": "url", "digest": "sha256:" + "0" * 64},
        "interfaces": {"inputs": {"type": "object"}, "outputs": {"type": "object"}},
        "permissions": {"network": "deny", "filesystem": "none", "devices": []},
        "runtime": {"sandbox": "process", "resources": {"cpu": "default", "memory": "default"}},
        "trust_level": "untrusted",
        "enabled": True,
        "execution": {"channel": "programmatic"},
        "implementation": {"kind": "python", "python": {"callable": "capability_builtins:echo"}},
    }
    validate_manifest(manifest)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "catalog.example" and request.url.path == "/catalog.json":
            return httpx.Response(200, json={"capabilities": [{"manifest": manifest}]})
        return httpx.Response(404, json={"error": "not found"})

    transport = httpx.MockTransport(handler)
    egress = EgressController(EgressConfig(allowlist=["https://catalog.example"], denylist=[], allow_private_networks=False), transport=transport)
    adapter = HttpCatalogAdapter(name="http", catalog_urls=["https://catalog.example/catalog.json"], egress=egress)
    cands = adapter.list(query="catalog", filters=None)
    assert len(cands) == 1
    assert cands[0].manifest["id"] == "catalog.tool"
