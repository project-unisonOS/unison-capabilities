from datetime import datetime, timedelta, timezone

import pytest

from errors import CapabilityPolicyError
from governance import ReplayGuard, authorize_execution, validate_governance_manifest


def manifest():
    return {"governance_version": "unison.capability-governance.v1", "governance": {"actions": ["draft"], "data_read": ["personal"], "data_write": [], "recipient_classes": [], "execution_location": "device", "risk": "low", "reversible": True, "cost_ceiling": "0", "confirmation": "draft-first", "accessibility": {"semantic": True}, "audit": {"owner_readable": True}, "retention": {"days": 7}, "egress": [], "filesystem": [], "devices": [], "timeout_seconds": 10, "resource_limits": {"cpu": "1", "memory": "128Mi"}, "signature": "sha256:test", "revocation_id": "cap:1"}}


def authority():
    return {"decision_id": "d1", "outcome": "allow", "principal_id": "p1", "assistant_id": "a1", "action": "draft", "grant_id": "g1", "expires_at": (datetime.now(timezone.utc) + timedelta(minutes=1)).isoformat(), "nonce": "n1"}


def test_legacy_manifest_is_disabled():
    with pytest.raises(CapabilityPolicyError, match="legacy"):
        validate_governance_manifest({})


def test_manifest_overreach_and_revocation_are_denied():
    with pytest.raises(CapabilityPolicyError, match="does not declare"):
        authorize_execution(manifest(), {**authority(), "action": "send"})
    with pytest.raises(CapabilityPolicyError, match="revoked"):
        authorize_execution(manifest(), authority(), revoked={"cap:1"})


def test_authority_replay_is_denied():
    guard = ReplayGuard(); guard.consume("n1")
    with pytest.raises(CapabilityPolicyError, match="replayed"):
        guard.consume("n1")
