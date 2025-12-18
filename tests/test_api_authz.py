from __future__ import annotations

from pathlib import Path

from fastapi.testclient import TestClient

from config import AuthConfig, AuthzConfig, BindConfig, EgressConfig, ServiceConfig, StoreConfig
from server import create_app


def _cfg(tmp_path: Path, *, token: str = "t") -> ServiceConfig:
    return ServiceConfig(
        bind=BindConfig(host="127.0.0.1", port=0, uds_path=None, unsafe_allow_nonlocal=False),
        auth=AuthConfig(mode="static_bearer", static_bearer_token=token, unsafe_allow_no_auth=False),
        authz=AuthzConfig(
            read_roles=["service"],
            run_roles=["service"],
            admin_roles=["operator", "admin"],
            install_allowed_services=[],
            remove_allowed_services=[],
        ),
        store=StoreConfig(base_dir=str(tmp_path / "store")),
        egress=EgressConfig(allowlist=[], denylist=[], allow_private_networks=False),
    )


def test_run_requires_auth(tmp_path: Path) -> None:
    app = create_app(_cfg(tmp_path))
    client = TestClient(app)
    r = client.post("/capability/run", json={"capability_id": "demo.echo", "args": {"text": "hi"}})
    assert r.status_code == 401


def test_install_more_privileged_than_run(tmp_path: Path) -> None:
    cfg = _cfg(tmp_path, token="secret-token")
    app = create_app(cfg)
    client = TestClient(app)

    headers = {"Authorization": "Bearer secret-token"}
    r1 = client.post("/capability/run", json={"capability_id": "demo.echo", "args": {"text": "hi"}}, headers=headers)
    # demo.echo is not installed; auth passes but the capability isn't found.
    assert r1.status_code in {404, 400, 500}

    r2 = client.post("/capability/install", json={"candidate": {"source": "unit", "manifest": {"id": "x"}}}, headers=headers)
    assert r2.status_code == 403


def test_install_allowed_by_service_allowlist(tmp_path: Path) -> None:
    cfg = _cfg(tmp_path, token="secret-token")
    cfg = ServiceConfig(
        bind=cfg.bind,
        auth=cfg.auth,
        authz=AuthzConfig(
            read_roles=["service"],
            run_roles=["service"],
            admin_roles=["operator", "admin"],
            install_allowed_services=["static-bearer"],
            remove_allowed_services=["static-bearer"],
        ),
        store=cfg.store,
        egress=cfg.egress,
    )
    app = create_app(cfg)
    client = TestClient(app)

    headers = {"Authorization": "Bearer secret-token"}
    r = client.post("/capability/install", json={"candidate": {"source": "unit", "manifest": {"id": "x"}}}, headers=headers)
    # Schema validation fails, but authz should pass (not 403/401).
    assert r.status_code == 400

