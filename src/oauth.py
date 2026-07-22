from __future__ import annotations

import json
import os
import time
import uuid
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, Optional
from urllib.parse import urlparse

from audit import AuditEmitter
from egress import EgressController
from errors import CapabilityPolicyError, CapabilityRunError
from credential_secrets import FileFernetSecretsBackend, SecretsBackend
from store import CapabilityStore


def _require_https(url: str) -> None:
    if urlparse(url).scheme != "https":
        raise CapabilityPolicyError("oauth endpoints must be https")


def _truthy(v: str | None) -> bool:
    return (v or "").strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class OAuthSession:
    session_id: str
    capability_id: str
    provider: str
    device_code_handle: str
    expires_at: float
    interval: int


@dataclass
class OAuthManager:
    store: CapabilityStore
    secrets: SecretsBackend
    egress: EgressController

    def _sessions_path(self) -> Path:
        p = self.store.base_dir / "tmp" / "oauth.sessions.json"
        p.parent.mkdir(parents=True, exist_ok=True)
        return p

    def _load_sessions(self) -> Dict[str, Dict[str, Any]]:
        p = self._sessions_path()
        if not p.exists():
            return {}
        raw = json.loads(p.read_text(encoding="utf-8"))
        return raw if isinstance(raw, dict) else {}

    def _write_sessions(self, sessions: Dict[str, Dict[str, Any]]) -> None:
        p = self._sessions_path()
        from atomic import atomic_write_json

        atomic_write_json(p, sessions, mode=0o600)

    def _provider_for_capability(self, capability_id: str) -> str:
        if capability_id.startswith("connector.google."):
            return "google"
        if capability_id.startswith("connector.microsoft."):
            return "microsoft"
        raise CapabilityPolicyError("capability is not an OAuth connector")

    def _scopes_for_capability(self, capability_id: str, provider: str) -> str:
        # Minimal read scopes; expand via policy/config in real deployments.
        if provider == "google":
            if capability_id.endswith(".calendar"):
                return "https://www.googleapis.com/auth/calendar.readonly"
            if capability_id.endswith(".email"):
                return "https://www.googleapis.com/auth/gmail.readonly"
            return "openid email"
        if provider == "microsoft":
            if capability_id.endswith(".calendar"):
                return "offline_access Calendars.Read"
            if capability_id.endswith(".email"):
                return "offline_access Mail.Read"
            return "offline_access User.Read"
        raise CapabilityPolicyError("unknown oauth provider")

    def _client_id(self, provider: str) -> str:
        if provider == "google":
            v = os.getenv("UNISON_OAUTH_GOOGLE_CLIENT_ID")
        else:
            v = os.getenv("UNISON_OAUTH_MICROSOFT_CLIENT_ID")
        if not v:
            raise CapabilityPolicyError(f"missing oauth client id for provider: {provider}")
        return v

    def _client_secret(self, provider: str) -> Optional[str]:
        if provider == "google":
            return os.getenv("UNISON_OAUTH_GOOGLE_CLIENT_SECRET")
        return os.getenv("UNISON_OAUTH_MICROSOFT_CLIENT_SECRET")

    def _device_code_endpoint(self, provider: str) -> str:
        if provider == "google":
            return "https://oauth2.googleapis.com/device/code"
        if provider == "microsoft":
            return "https://login.microsoftonline.com/common/oauth2/v2.0/devicecode"
        raise CapabilityPolicyError("unknown oauth provider")

    def _token_endpoint(self, provider: str) -> str:
        if provider == "google":
            return "https://oauth2.googleapis.com/token"
        if provider == "microsoft":
            return "https://login.microsoftonline.com/common/oauth2/v2.0/token"
        raise CapabilityPolicyError("unknown oauth provider")

    def start(self, *, capability_id: str, principal: Dict[str, Any], audit: AuditEmitter) -> Dict[str, Any]:
        manifest = self.store.merged_catalog().get(capability_id)
        if not manifest:
            raise CapabilityPolicyError("capability not found")
        if manifest.get("requires_oauth") is not True:
            raise CapabilityPolicyError("capability does not require oauth")
        if manifest.get("enabled") is True:
            raise CapabilityPolicyError("capability already enabled")

        provider = self._provider_for_capability(capability_id)
        client_id = self._client_id(provider)
        scopes = self._scopes_for_capability(capability_id, provider)

        device_url = self._device_code_endpoint(provider)
        token_url = self._token_endpoint(provider)
        _require_https(device_url)
        _require_https(token_url)

        audit.emit(event="oauth.start", principal=principal, outcome="allow", resource_type="capability", resource_id=capability_id)
        resp = self.egress.request(
            "POST",
            device_url,
            data={"client_id": client_id, "scope": scopes},
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=10.0,
        )
        resp.raise_for_status()
        data = resp.json()
        device_code = data.get("device_code")
        user_code = data.get("user_code")
        verification_uri = data.get("verification_uri") or data.get("verification_url")
        expires_in = int(data.get("expires_in") or 600)
        interval = int(data.get("interval") or 5)
        if not device_code or not user_code or not verification_uri:
            raise CapabilityRunError("oauth device flow response missing required fields")

        session_id = uuid.uuid4().hex
        device_handle = f"secret://oauth/session/{session_id}/device_code"
        self.secrets.put(handle=device_handle, value={"device_code": str(device_code)})

        sessions = self._load_sessions()
        sessions[session_id] = {
            "capability_id": capability_id,
            "provider": provider,
            "device_code_handle": device_handle,
            "expires_at": time.time() + expires_in,
            "interval": interval,
        }
        self._write_sessions(sessions)

        return {
            "session_id": session_id,
            "provider": provider,
            "user_code": user_code,
            "verification_uri": verification_uri,
            "expires_in": expires_in,
            "interval": interval,
            "message": data.get("message"),
        }

    def complete(self, *, session_id: str, principal: Dict[str, Any], audit: AuditEmitter) -> Dict[str, Any]:
        sessions = self._load_sessions()
        s = sessions.get(session_id)
        if not isinstance(s, dict):
            raise CapabilityPolicyError("unknown oauth session")
        if time.time() > float(s.get("expires_at") or 0):
            raise CapabilityPolicyError("oauth session expired")
        provider = str(s.get("provider") or "")
        capability_id = str(s.get("capability_id") or "")
        device_handle = str(s.get("device_code_handle") or "")
        device_code = self.secrets.get(handle=device_handle).get("device_code")
        if not device_code:
            raise CapabilityPolicyError("missing device_code secret for session")

        client_id = self._client_id(provider)
        client_secret = self._client_secret(provider)
        token_url = self._token_endpoint(provider)
        _require_https(token_url)

        audit.emit(event="oauth.complete", principal=principal, outcome="allow", resource_type="capability", resource_id=capability_id)

        token_req = {
            "client_id": client_id,
            "device_code": device_code,
            "grant_type": "urn:ietf:params:oauth:grant-type:device_code",
        }
        if client_secret:
            token_req["client_secret"] = client_secret
        resp = self.egress.request(
            "POST",
            token_url,
            data=token_req,
            headers={"Content-Type": "application/x-www-form-urlencoded"},
            timeout=10.0,
        )
        data = resp.json() if resp.status_code < 500 else {}
        if resp.status_code >= 400:
            err = str(data.get("error") or "oauth_error")
            if err in {"authorization_pending", "slow_down"}:
                return {"status": "pending", "error": err, "interval": int(s.get("interval") or 5)}
            raise CapabilityRunError(f"oauth token exchange failed: {err}")

        refresh_token = data.get("refresh_token")
        if not refresh_token:
            raise CapabilityRunError("oauth token response missing refresh_token")

        username = str(principal.get("username") or "unknown")
        token_handle = f"secret://oauth/{provider}/{username}/{capability_id}/refresh_token"
        self.secrets.put(handle=token_handle, value={"refresh_token": str(refresh_token)})

        # Update local manifest to enable connector and bind secret reference.
        merged = self.store.merged_catalog()
        m = dict(merged.get(capability_id) or {})
        if not m:
            raise CapabilityPolicyError("capability not found")
        m["enabled"] = True
        secrets = [s for s in (m.get("secrets") or []) if isinstance(s, dict)]
        secrets = [s for s in secrets if str(s.get("name") or "") != "OAUTH_REFRESH_TOKEN"]
        secrets.append({"name": "OAUTH_REFRESH_TOKEN", "ref": token_handle})
        m["secrets"] = secrets
        self.store.upsert_local(m)

        # Cleanup session device code secret and state.
        self.secrets.delete(handle=device_handle)
        sessions.pop(session_id, None)
        self._write_sessions(sessions)

        audit.emit(event="capability.enabled", principal=principal, outcome="allow", resource_type="capability", resource_id=capability_id)
        return {"status": "enabled", "capability_id": capability_id}


def default_oauth_manager(*, store: CapabilityStore, egress: EgressController) -> OAuthManager:
    secrets = FileFernetSecretsBackend.from_env(base_dir=store.base_dir)
    return OAuthManager(store=store, secrets=secrets, egress=egress)
