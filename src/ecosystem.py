"""Phase 8 capability supply-chain controls.

The helpers in this module are deliberately independent of any registry.  A
package is accepted only when its canonical manifest is signed by a configured
publisher, its API range is compatible, and its revocation identity is active.
"""
from __future__ import annotations

import base64
import json
from dataclasses import dataclass, field
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from errors import CapabilityPolicyError


PERMISSION_FIELDS = (
    "actions",
    "data_read",
    "data_write",
    "recipient_classes",
    "egress",
    "filesystem",
    "devices",
)


def canonical_manifest(manifest: dict[str, Any]) -> bytes:
    unsigned = json.loads(json.dumps(manifest))
    governance = unsigned.get("governance")
    if isinstance(governance, dict):
        governance.pop("signature", None)
    return json.dumps(unsigned, sort_keys=True, separators=(",", ":"), ensure_ascii=False).encode()


def sign_manifest(manifest: dict[str, Any], private_key: Ed25519PrivateKey, *, publisher: str) -> dict[str, Any]:
    signed = json.loads(json.dumps(manifest))
    governance = signed.setdefault("governance", {})
    governance["publisher"] = publisher
    governance.pop("signature", None)
    signature = private_key.sign(canonical_manifest(signed))
    governance["signature"] = "ed25519:" + base64.b64encode(signature).decode("ascii")
    return signed


def verify_manifest_signature(manifest: dict[str, Any], trusted_publishers: dict[str, Ed25519PublicKey]) -> None:
    governance = manifest.get("governance")
    if not isinstance(governance, dict):
        raise CapabilityPolicyError("capability governance is required")
    publisher = governance.get("publisher")
    encoded = governance.get("signature")
    if publisher not in trusted_publishers or not isinstance(encoded, str) or not encoded.startswith("ed25519:"):
        raise CapabilityPolicyError("capability publisher or signature is not trusted")
    try:
        signature = base64.b64decode(encoded.removeprefix("ed25519:"), validate=True)
        trusted_publishers[publisher].verify(signature, canonical_manifest(manifest))
    except (InvalidSignature, ValueError) as exc:
        raise CapabilityPolicyError("capability signature verification failed") from exc


def permission_diff(previous: dict[str, Any], candidate: dict[str, Any]) -> dict[str, list[str]]:
    before = previous.get("governance") if isinstance(previous.get("governance"), dict) else {}
    after = candidate.get("governance") if isinstance(candidate.get("governance"), dict) else {}
    added: list[str] = []
    removed: list[str] = []
    for field_name in PERMISSION_FIELDS:
        old_values = {str(value) for value in before.get(field_name, [])}
        new_values = {str(value) for value in after.get(field_name, [])}
        added.extend(f"{field_name}:{value}" for value in sorted(new_values - old_values))
        removed.extend(f"{field_name}:{value}" for value in sorted(old_values - new_values))
    if before.get("risk") != after.get("risk"):
        added.append(f"risk:{before.get('risk')}->{after.get('risk')}")
    if before.get("confirmation") != after.get("confirmation"):
        added.append(f"confirmation:{before.get('confirmation')}->{after.get('confirmation')}")
    return {"added": added, "removed": removed}


def require_permission_review(previous: dict[str, Any], candidate: dict[str, Any], *, approved: bool) -> None:
    diff = permission_diff(previous, candidate)
    if diff["added"] and not approved:
        raise CapabilityPolicyError("capability update expands permissions and requires explicit review")


def require_compatibility(manifest: dict[str, Any], *, host_api_major: int) -> None:
    compatibility = manifest.get("compatibility")
    if not isinstance(compatibility, dict):
        raise CapabilityPolicyError("capability compatibility range is required")
    minimum = int(compatibility.get("min_host_api", -1))
    maximum = int(compatibility.get("max_host_api", -1))
    if not minimum <= host_api_major <= maximum:
        raise CapabilityPolicyError("capability is incompatible with this host")


@dataclass
class RevocationRegistry:
    revoked: set[str] = field(default_factory=set)

    def revoke(self, revocation_id: str) -> None:
        if not revocation_id:
            raise CapabilityPolicyError("revocation identity is required")
        self.revoked.add(revocation_id)

    def restore(self, revocation_id: str) -> None:
        self.revoked.discard(revocation_id)

    def require_active(self, manifest: dict[str, Any]) -> None:
        governance = manifest.get("governance") or {}
        if governance.get("revocation_id") in self.revoked:
            raise CapabilityPolicyError("capability is revoked")
