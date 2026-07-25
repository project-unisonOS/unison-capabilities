import pytest

from semantic_targets import SemanticTargetAuthority, TargetBindingError


def test_target_is_revalidated_immediately_before_action():
    authority = SemanticTargetAuthority(b"x" * 32, clock=lambda: 100)
    target = authority.bind(capability="form.submit", target_id="form-1", person_id="p", state_version="7")
    authority.authorize(target, capability="form.submit", person_id="p", current_state_version="7")
    with pytest.raises(TargetBindingError, match="state changed"):
        authority.authorize(target, capability="form.submit", person_id="p", current_state_version="8")


def test_target_cannot_transfer_people_or_capabilities():
    authority = SemanticTargetAuthority(b"x" * 32, clock=lambda: 100)
    target = authority.bind(capability="payment.send", target_id="invoice", person_id="p", state_version="1")
    with pytest.raises(TargetBindingError):
        authority.authorize(target, capability="payment.send", person_id="other", current_state_version="1")
    with pytest.raises(TargetBindingError):
        authority.authorize(target, capability="email.send", person_id="p", current_state_version="1")


def test_expired_and_tampered_targets_stop():
    now = [100]
    authority = SemanticTargetAuthority(b"x" * 32, clock=lambda: now[0])
    target = authority.bind(capability="form.submit", target_id="form", person_id="p", state_version="1", ttl_seconds=1)
    now[0] = 101
    with pytest.raises(TargetBindingError, match="expired"):
        authority.authorize(target, capability="form.submit", person_id="p", current_state_version="1")
