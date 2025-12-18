from __future__ import annotations

import os
from dataclasses import dataclass
from typing import Any, Dict, Iterable, Optional, Set

from errors import CapabilityPolicyError


def _truthy(value: str | None) -> bool:
    return (value or "").strip().lower() in {"1", "true", "yes", "on"}


@dataclass(frozen=True)
class CapabilityPolicy:
    trust_allow: Set[str]

    @classmethod
    def from_env(cls) -> "CapabilityPolicy":
        allow = os.getenv("UNISON_CAPABILITY_TRUST_ALLOW", "local,verified")
        trust_allow = {x.strip() for x in allow.split(",") if x.strip()}
        if _truthy(os.getenv("UNISON_CAPABILITY_ALLOW_COMMUNITY", "false")):
            trust_allow.add("community")
        if _truthy(os.getenv("UNISON_CAPABILITY_ALLOW_UNTRUSTED", "false")):
            trust_allow.add("untrusted")
        return cls(trust_allow=trust_allow)

    def enforce_install(self, manifest: Dict[str, Any]) -> None:
        trust = str(manifest.get("trust_level") or "")
        if trust not in self.trust_allow:
            raise CapabilityPolicyError(f"trust_level not allowed by policy: {trust}")

        if "secrets" in manifest:
            secrets = manifest.get("secrets")
            if not isinstance(secrets, list):
                raise CapabilityPolicyError("secrets must be a list of references")
            for s in secrets:
                if not isinstance(s, dict) or "ref" not in s or "value" in s:
                    raise CapabilityPolicyError("secrets must be references only (no values)")

    def enforce_run(self, manifest: Dict[str, Any], *, requested_channel: Optional[str] = None) -> None:
        if manifest.get("enabled") is False:
            raise CapabilityPolicyError("capability disabled")

        if manifest.get("requires_oauth") is True:
            secrets = manifest.get("secrets") if isinstance(manifest.get("secrets"), list) else []
            has_oauth = any(isinstance(s, dict) and str(s.get("name") or "").upper().startswith("OAUTH_") for s in secrets)
            if not has_oauth:
                raise CapabilityPolicyError("capability requires oauth onboarding")

        declared = (manifest.get("execution") or {}).get("channel")
        if declared in {"programmatic", "vdi_vpn"} and requested_channel and requested_channel != declared:
            raise CapabilityPolicyError(f"execution channel mismatch: declared={declared} requested={requested_channel}")
