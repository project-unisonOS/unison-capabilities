from __future__ import annotations

import os
import platform
import shutil
import socket
import sys
import time
from pathlib import Path
from typing import Any, Dict, List

from errors import CapabilityRunError


def _split_paths(value: str) -> list[Path]:
    paths: list[Path] = []
    for raw in (value or "").split(","):
        raw = raw.strip()
        if not raw:
            continue
        paths.append(Path(raw).expanduser().resolve())
    return paths


def _allowed_roots(kind: str) -> list[Path]:
    if kind == "read":
        val = os.getenv("UNISON_CAPABILITY_FS_READ_ALLOW", "/etc,/proc,/sys,/var/lib/unison,/tmp")
    else:
        val = os.getenv("UNISON_CAPABILITY_FS_WRITE_ALLOW", "/var/lib/unison,/tmp")
    return _split_paths(val)


def _ensure_under_roots(path: Path, roots: list[Path]) -> None:
    rp = path.expanduser().resolve()
    for root in roots:
        try:
            rp.relative_to(root)
            return
        except Exception:
            continue
    raise CapabilityRunError("path not permitted by policy")


def host_info(args: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "hostname": socket.gethostname(),
        "platform": platform.platform(),
        "kernel": {"system": platform.system(), "release": platform.release(), "version": platform.version()},
        "python": {"version": sys.version.split()[0]},
        "time": {"unix": int(time.time())},
    }


def host_resources(args: Dict[str, Any]) -> Dict[str, Any]:
    roots = args.get("disk_roots") or ["/"]
    if not isinstance(roots, list):
        roots = ["/"]
    disks = []
    for r in roots[:5]:
        try:
            usage = shutil.disk_usage(str(r))
            disks.append({"path": str(r), "total": usage.total, "used": usage.used, "free": usage.free})
        except Exception:
            continue
    return {
        "cpu_count": os.cpu_count(),
        "memory": _meminfo_summary(),
        "disks": disks,
    }


def _meminfo_summary() -> Dict[str, Any]:
    try:
        data = Path("/proc/meminfo").read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return {}
    out: Dict[str, Any] = {}
    for line in data.splitlines()[:50]:
        if ":" not in line:
            continue
        k, v = line.split(":", 1)
        out[k.strip()] = v.strip()
    return out


def host_net_ifaces(args: Dict[str, Any]) -> Dict[str, Any]:
    out: Dict[str, Any] = {}
    base = Path("/sys/class/net")
    if not base.exists():
        return {"interfaces": []}
    ifaces: List[Dict[str, Any]] = []
    for p in sorted(base.iterdir()):
        if not p.is_dir():
            continue
        name = p.name
        if name == "lo":
            continue
        iface = {"name": name}
        for f in ("address", "operstate", "mtu"):
            try:
                iface[f] = (p / f).read_text(encoding="utf-8").strip()
            except Exception:
                continue
        ifaces.append(iface)
        if len(ifaces) >= 32:
            break
    return {"interfaces": ifaces}


def process_list(args: Dict[str, Any]) -> Dict[str, Any]:
    limit = args.get("limit", 25)
    try:
        limit_i = int(limit)
    except Exception:
        limit_i = 25
    limit_i = max(1, min(limit_i, 200))

    procs: list[Dict[str, Any]] = []
    proc_root = Path("/proc")
    if not proc_root.exists():
        return {"processes": []}
    for p in proc_root.iterdir():
        if not p.name.isdigit():
            continue
        pid = int(p.name)
        try:
            cmdline = (p / "cmdline").read_text(encoding="utf-8", errors="ignore").replace("\x00", " ").strip()
            comm = (p / "comm").read_text(encoding="utf-8", errors="ignore").strip()
            stat = (p / "stat").read_text(encoding="utf-8", errors="ignore").split()
            procs.append({"pid": pid, "comm": comm, "cmdline": cmdline, "state": stat[2] if len(stat) > 2 else ""})
        except Exception:
            continue
        if len(procs) >= limit_i:
            break
    return {"processes": procs}


def fs_read(args: Dict[str, Any]) -> Dict[str, Any]:
    path = args.get("path")
    if not isinstance(path, str) or not path:
        raise CapabilityRunError("path required")
    p = Path(path)
    _ensure_under_roots(p, _allowed_roots("read"))
    text = p.read_text(encoding="utf-8", errors="replace")
    max_bytes = int(args.get("max_bytes") or 64 * 1024)
    if len(text.encode("utf-8")) > max_bytes:
        text = text.encode("utf-8")[:max_bytes].decode("utf-8", errors="ignore")
    return {"path": str(p), "content": text}


def fs_write(args: Dict[str, Any]) -> Dict[str, Any]:
    path = args.get("path")
    content = args.get("content")
    if not isinstance(path, str) or not path:
        raise CapabilityRunError("path required")
    if not isinstance(content, str):
        raise CapabilityRunError("content must be string")
    p = Path(path)
    _ensure_under_roots(p, _allowed_roots("write"))
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(content, encoding="utf-8")
    return {"path": str(p), "bytes_written": len(content.encode("utf-8"))}


def connector_status(manifest: Dict[str, Any], args: Dict[str, Any]) -> Dict[str, Any]:
    return {
        "id": manifest.get("id"),
        "enabled": manifest.get("enabled", True),
        "requires_oauth": manifest.get("requires_oauth", False),
        "secrets": [{"name": s.get("name"), "ref": s.get("ref")} for s in (manifest.get("secrets") or []) if isinstance(s, dict)],
        "note": "Connector wrappers are placeholders; execution is expected via MCP/connector services once configured.",
    }

