from __future__ import annotations

import hashlib
import logging
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any, Dict, Optional

try:
    from unison_common.logging import log_json
except Exception:  # pragma: no cover
    log_json = None


def _hash_id(value: str) -> str:
    if not value:
        return ""
    return hashlib.sha256(value.encode("utf-8")).hexdigest()[:16]


@dataclass(frozen=True)
class AuditEmitter:
    service: str

    def emit(
        self,
        *,
        event: str,
        principal: Optional[Dict[str, Any]] = None,
        request_id: Optional[str] = None,
        resource_type: Optional[str] = None,
        resource_id: Optional[str] = None,
        classification: str = "internal",
        outcome: str = "allow",
        reason: Optional[str] = None,
        extra: Optional[Dict[str, Any]] = None,
        severity: str = "INFO",
    ) -> None:
        payload: Dict[str, Any] = {
            "ts": datetime.now(timezone.utc).isoformat(),
            "service": self.service,
            "severity": severity,
            "request_id": request_id,
            "principal": {
                "user_id": principal.get("username") if isinstance(principal, dict) else None,
                "role": (principal.get("roles") if isinstance(principal, dict) else None),
                "spiffe_id": None,
            },
            "resource": {
                "type": resource_type,
                "id": _hash_id(resource_id or ""),
                "classification": classification,
            },
            "decision": {"outcome": outcome, "policy": None, "reason": reason},
        }
        if extra:
            payload.update(extra)
        if log_json:
            lvl = logging.INFO
            if severity.upper() == "WARN":
                lvl = logging.WARNING
            if severity.upper() == "ERROR":
                lvl = logging.ERROR
            log_json(lvl, event, **payload)
        else:
            logging.info("%s", payload)
