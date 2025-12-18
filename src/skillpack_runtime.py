from __future__ import annotations

from pathlib import Path
from typing import Any, Dict

from errors import CapabilityRunError


def run(manifest: Dict[str, Any], args: Dict[str, Any]) -> Dict[str, Any]:
    origin = manifest.get("origin") if isinstance(manifest.get("origin"), dict) else {}
    path = origin.get("path")
    if not isinstance(path, str) or not path:
        raise CapabilityRunError("skill pack origin.path required")
    p = Path(path)
    if not p.is_absolute():
        # Treat as relative to repo root in images/source checkouts.
        p = Path(__file__).resolve().parents[1] / p
    if not p.exists():
        raise CapabilityRunError(f"skill pack file not found: {p}")
    content = p.read_text(encoding="utf-8", errors="replace")
    return {"skill_pack_id": manifest.get("id"), "content": content}

