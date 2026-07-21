"""Fail-closed validation for Phase 3 capability execution authority."""
from __future__ import annotations

from datetime import datetime, timezone
from typing import Any

from errors import CapabilityPolicyError


REQUIRED_MANIFEST_FIELDS = {
    "actions", "data_read", "data_write", "recipient_classes", "execution_location",
    "risk", "reversible", "cost_ceiling", "confirmation", "accessibility",
    "audit", "retention", "egress", "filesystem", "devices", "timeout_seconds",
    "resource_limits", "signature", "revocation_id",
}


def validate_governance_manifest(manifest: dict[str, Any]) -> dict[str, Any]:
    governance = manifest.get("governance")
    if manifest.get("governance_version") != "unison.capability-governance.v1" or not isinstance(governance, dict):
        raise CapabilityPolicyError("legacy or unknown capability governance is disabled")
    missing = sorted(REQUIRED_MANIFEST_FIELDS - governance.keys())
    if missing:
        raise CapabilityPolicyError("incomplete capability governance: " + ", ".join(missing))
    if governance["execution_location"] not in {"device", "sandboxed-container"}:
        raise CapabilityPolicyError("unknown execution location")
    if governance["risk"] not in {"low", "medium", "high", "critical"}:
        raise CapabilityPolicyError("unknown capability risk")
    if float(governance["timeout_seconds"]) <= 0 or float(governance["timeout_seconds"]) > 300:
        raise CapabilityPolicyError("capability timeout is outside the bounded range")
    if not governance["signature"] or not governance["revocation_id"]:
        raise CapabilityPolicyError("signature and revocation identity are required")
    return manifest


def authorize_execution(manifest: dict[str, Any], authority: dict[str, Any], *, revoked: set[str] | None = None) -> None:
    validate_governance_manifest(manifest)
    governance = manifest["governance"]
    required = {"decision_id", "outcome", "principal_id", "assistant_id", "action", "grant_id", "expires_at", "nonce"}
    missing = sorted(key for key in required if not authority.get(key))
    if missing:
        raise CapabilityPolicyError("incomplete execution authority: " + ", ".join(missing))
    if authority["outcome"] != "allow":
        raise CapabilityPolicyError("trust decision does not allow execution")
    if authority["action"] not in governance["actions"]:
        raise CapabilityPolicyError("manifest does not declare the requested action")
    if datetime.fromisoformat(authority["expires_at"]) <= datetime.now(timezone.utc):
        raise CapabilityPolicyError("execution authority expired")
    if revoked and governance["revocation_id"] in revoked:
        raise CapabilityPolicyError("capability is revoked")


class ReplayGuard:
    def __init__(self):
        self._seen: set[str] = set()

    def consume(self, nonce: str) -> None:
        if nonce in self._seen:
            raise CapabilityPolicyError("execution authority replayed")
        self._seen.add(nonce)
