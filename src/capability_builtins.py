from __future__ import annotations

from datetime import datetime, timezone
from typing import Any, Dict


def echo(args: Dict[str, Any]) -> Dict[str, Any]:
    text = args.get("text")
    return {"echo": text}


def time_now(args: Dict[str, Any]) -> Dict[str, Any]:
    return {"iso": datetime.now(timezone.utc).isoformat()}

