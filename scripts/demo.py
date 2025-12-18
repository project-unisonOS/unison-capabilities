from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path

import httpx
from cryptography.fernet import Fernet

from audit import AuditEmitter
from config import EgressConfig
from discovery import StaticCatalogAdapter
from egress import EgressController
from execution import ExecutionEngine
from oauth import OAuthManager
from policy import CapabilityPolicy
from resolver import CapabilityResolver
from secrets import FileFernetSecretsBackend
from store import CapabilityStore


def main() -> None:
    with tempfile.TemporaryDirectory(prefix="unison-capability-demo-") as td:
        base_dir = Path(td)
        store = CapabilityStore(base_dir=base_dir)
        audit = AuditEmitter(service="unison-capability-demo")

        # Egress: allow only oauth2.googleapis.com (demo uses MockTransport, no real network).
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
        egress = EgressController(EgressConfig(allowlist=["https://oauth2.googleapis.com"]), transport=transport)

        # Seed base catalog by pointing store at the shipped base manifest.
        store = CapabilityStore(base_dir=base_dir, base_catalog_path=Path(__file__).resolve().parents[1] / "manifests" / "manifest.base.json")

        resolver = CapabilityResolver(
            store=store,
            policy=CapabilityPolicy(trust_allow={"local", "verified", "community"}),
            exec_engine=ExecutionEngine(egress=egress),
            registries=[StaticCatalogAdapter(name="static_catalog", catalog_path=str(Path(__file__).resolve().parents[1] / "registries" / "static_catalog.json"))],
        )

        # 1) Intent resolves to seeded local tool (no install).
        c1 = resolver.resolve(step={"intent": "host.info", "constraints": {}})
        out1 = resolver.run(capability_id=str(c1.manifest["id"]), args={})
        print("demo 1 (seeded local tool):", json.dumps(out1, indent=2))

        # 2) Missing intent triggers registry suggestion (no auto-install).
        results = resolver.search(intent="echo", constraints={})
        top = results[0]
        print("demo 2 (registry suggestion top candidate):", top.source, top.manifest["id"])

        # 3) OAuth start/complete enables a connector; secrets stored by reference only.
        os.environ["UNISON_CAPABILITY_SECRETS_KEY"] = Fernet.generate_key().decode("utf-8")
        os.environ["UNISON_OAUTH_GOOGLE_CLIENT_ID"] = "client-id"
        secrets = FileFernetSecretsBackend.from_env(base_dir=store.base_dir)
        oauth = OAuthManager(store=store, secrets=secrets, egress=egress)
        principal = {"username": "service-orchestrator", "roles": ["service"]}

        start = oauth.start(capability_id="connector.google.calendar", principal=principal, audit=audit)
        print("demo 3a (oauth start):", {k: v for k, v in start.items() if k != "session_id"}, "session_id=", start["session_id"])

        complete = oauth.complete(session_id=start["session_id"], principal=principal, audit=audit)
        print("demo 3b (oauth complete):", complete)

        enabled_manifest = resolver.get(capability_id="connector.google.calendar")
        print("demo 3c (enabled manifest secrets refs):", enabled_manifest.get("enabled"), enabled_manifest.get("secrets"))


if __name__ == "__main__":
    main()
