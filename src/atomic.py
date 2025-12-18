from __future__ import annotations

import json
import os
import tempfile
from pathlib import Path
from typing import Any, Dict


def atomic_write_text(path: Path, data: str, *, mode: int = 0o600) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    fd, tmp = tempfile.mkstemp(prefix=path.name + ".", dir=str(path.parent))
    try:
        os.fchmod(fd, mode)
        with os.fdopen(fd, "w", encoding="utf-8") as f:
            f.write(data)
            f.flush()
            os.fsync(f.fileno())
        os.replace(tmp, path)
        dir_fd = os.open(str(path.parent), os.O_DIRECTORY)
        try:
            os.fsync(dir_fd)
        finally:
            os.close(dir_fd)
    finally:
        try:
            os.unlink(tmp)
        except FileNotFoundError:
            pass


def atomic_write_json(path: Path, payload: Dict[str, Any], *, mode: int = 0o600) -> None:
    atomic_write_text(path, json.dumps(payload, indent=2, sort_keys=True) + "\n", mode=mode)

