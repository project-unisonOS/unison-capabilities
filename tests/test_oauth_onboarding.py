from __future__ import annotations

import logging
import os
from pathlib import Path

import httpx
from cryptography.fernet import Fernet
from fastapi.testclient import TestClient

from config import AuthConfig, AuthzConfig, BindConfig, EgressConfig, ServiceConfig, StoreConfig
from egress import EgressController
from server import create_app
from store import CapabilityStore


def test_oauth_device_flow_enables_connector_without_secret_leak(tmp_path: Path, caplog, monkeypatch) -> None:
    monkeypatch.setenv("UNISON_CAPABILITY_SECRETS_KEY", Fernet.generate_key().decode("utf-8"))
    monkeypatch.setenv("UNISON_OAUTH_GOOGLE_CLIENT_ID", "client-id")
    monkeypatch.delenv("UNISON_OAUTH_GOOGLE_CLIENT_SECRET", raising=False)

    def handler(request: httpx.Request) -> httpx.Response:
        if request.url.host == "oauth2.googleapis.com" and request.url.path == "/device/code":
            return httpx.Response(
                200,
                json={
                    "device_code": "device-code-secret",
                    "user_code": "ABCD-EFGH",
                    "verification_uri": "https://example.com/verify",
                    "expires_in": 600,
                    "interval": 1,
                },
            )
        if request.url.host == "oauth2.googleapis.com" and request.url.path == "/token":
            return httpx.Response(200, json={"refresh_token": "refresh-token-secret"})
        return httpx.Response(404, json={"error": "not found"})

    transport = httpx.MockTransport(handler)
    egress = EgressController(
        EgressConfig(allowlist=["https://oauth2.googleapis.com"], denylist=[], allow_private_networks=False),
        transport=transport,
    )

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
        egress=egress.cfg,
    )
    app = create_app(cfg, egress_controller=egress)
    client = TestClient(app)

    caplog.set_level(logging.INFO)
    h = {"Authorization": "Bearer t"}

    r1 = client.post("/capability/oauth/start", json={"capability_id": "connector.google.calendar"}, headers=h)
    assert r1.status_code == 200
    session_id = r1.json()["session_id"]

    r2 = client.post("/capability/oauth/complete", json={"session_id": session_id}, headers=h)
    assert r2.status_code == 200
    assert r2.json()["status"] == "enabled"

    # Connector is enabled in local catalog (not base).
    r3 = client.get("/capability/get/connector.google.calendar", headers=h)
    assert r3.status_code == 200
    manifest = r3.json()["manifest"]
    assert manifest["enabled"] is True
    assert manifest["requires_oauth"] is True
    refs = [s["ref"] for s in manifest.get("secrets") or [] if isinstance(s, dict) and s.get("name") == "OAUTH_REFRESH_TOKEN"]
    assert len(refs) == 1
    assert refs[0].startswith("secret://oauth/google/")

    # Secrets are not present in logs.
    joined = "\n".join([rec.getMessage() for rec in caplog.records])
    assert "device-code-secret" not in joined
    assert "refresh-token-secret" not in joined

