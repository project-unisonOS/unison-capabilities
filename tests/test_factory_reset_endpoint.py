from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from config import AuthConfig, AuthzConfig, BindConfig, EgressConfig, ServiceConfig, StoreConfig
from server import create_app


def test_factory_reset_endpoint_deletes_local(tmp_path: Path) -> None:
    cfg = ServiceConfig(
        bind=BindConfig(host="127.0.0.1", port=0, uds_path=None, unsafe_allow_nonlocal=False),
        auth=AuthConfig(mode="static_bearer", static_bearer_token="t", unsafe_allow_no_auth=False),
        authz=AuthzConfig(
            read_roles=["service"],
            run_roles=["service"],
            admin_roles=["admin"],
            install_allowed_services=["static-bearer"],
            remove_allowed_services=["static-bearer"],
        ),
        store=StoreConfig(base_dir=str(tmp_path / "store")),
        egress=EgressConfig(allowlist=[], denylist=[], allow_private_networks=False),
    )
    app = create_app(cfg)
    client = TestClient(app)
    headers = {"Authorization": "Bearer t"}

    # Create a local manifest file.
    store_dir = Path(cfg.store.base_dir)
    store_dir.mkdir(parents=True, exist_ok=True)
    (store_dir / "manifest.local.json").write_text('{"capabilities": []}\n', encoding="utf-8")

    r = client.post("/capability/factory_reset", headers=headers)
    assert r.status_code == 200
    assert (store_dir / "manifest.local.json").exists() is False

