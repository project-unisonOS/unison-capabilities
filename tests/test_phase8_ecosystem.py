import copy

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from ecosystem import (
    RevocationRegistry,
    permission_diff,
    require_compatibility,
    require_permission_review,
    sign_manifest,
    verify_manifest_signature,
)
from errors import CapabilityPolicyError


def manifest():
    return {
        "id": "org.example.drafts",
        "version": "1.0.0",
        "compatibility": {"min_host_api": 1, "max_host_api": 1},
        "governance": {
            "actions": ["draft"],
            "data_read": ["message.subject"],
            "data_write": [],
            "recipient_classes": [],
            "egress": ["mail.example.test"],
            "filesystem": [],
            "devices": [],
            "risk": "low",
            "confirmation": "draft-first",
            "revocation_id": "org.example.drafts:1",
        },
    }


def test_signed_manifest_rejects_tampering_and_unknown_publishers():
    private = Ed25519PrivateKey.generate()
    signed = sign_manifest(manifest(), private, publisher="project-unisonOS")
    verify_manifest_signature(signed, {"project-unisonOS": private.public_key()})
    tampered = copy.deepcopy(signed)
    tampered["governance"]["actions"].append("send")
    with pytest.raises(CapabilityPolicyError, match="verification failed"):
        verify_manifest_signature(tampered, {"project-unisonOS": private.public_key()})
    with pytest.raises(CapabilityPolicyError, match="not trusted"):
        verify_manifest_signature(signed, {})


def test_permission_upgrade_requires_explicit_review():
    candidate = copy.deepcopy(manifest())
    candidate["governance"]["actions"].append("send")
    candidate["governance"]["egress"].append("new.example.test")
    assert permission_diff(manifest(), candidate)["added"] == [
        "actions:send",
        "egress:new.example.test",
    ]
    with pytest.raises(CapabilityPolicyError, match="explicit review"):
        require_permission_review(manifest(), candidate, approved=False)
    require_permission_review(manifest(), candidate, approved=True)


def test_compatibility_and_revocation_fail_closed():
    require_compatibility(manifest(), host_api_major=1)
    with pytest.raises(CapabilityPolicyError, match="incompatible"):
        require_compatibility(manifest(), host_api_major=2)
    registry = RevocationRegistry()
    registry.revoke("org.example.drafts:1")
    with pytest.raises(CapabilityPolicyError, match="revoked"):
        registry.require_active(manifest())
    registry.restore("org.example.drafts:1")
    registry.require_active(manifest())
