from __future__ import annotations

import logging
from pathlib import Path

from fastapi.testclient import TestClient

from config import AuthConfig, AuthzConfig, BindConfig, EgressConfig, ServiceConfig, StoreConfig
from server import create_app


def test_audit_does_not_log_bearer_token(tmp_path: Path, caplog) -> None:
    cfg = ServiceConfig(
        bind=BindConfig(host="127.0.0.1", port=0, uds_path=None, unsafe_allow_nonlocal=False),
        auth=AuthConfig(mode="static_bearer", static_bearer_token="super-secret-token", unsafe_allow_no_auth=False),
        authz=AuthzConfig(
            read_roles=["service"],
            run_roles=["service"],
            admin_roles=["service"],
            install_allowed_services=["static-bearer"],
            remove_allowed_services=["static-bearer"],
        ),
        store=StoreConfig(base_dir=str(tmp_path / "store")),
        egress=EgressConfig(allowlist=[], denylist=[], allow_private_networks=False),
    )
    app = create_app(cfg)
    client = TestClient(app)

    caplog.set_level(logging.INFO)
    r = client.get("/capability/list", headers={"Authorization": "Bearer super-secret-token"})
    assert r.status_code in {200, 500}

    joined = "\n".join([rec.getMessage() for rec in caplog.records])
    assert "super-secret-token" not in joined

