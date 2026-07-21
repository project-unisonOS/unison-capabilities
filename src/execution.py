from __future__ import annotations

import importlib
import inspect
import json
import subprocess
import os
from dataclasses import dataclass
from typing import Any, Dict, Optional

import httpx

from errors import CapabilityRunError
from egress import EgressController, enforce_manifest_network


def _load_callable(spec: str):
    module_name, fn_name = spec.split(":", 1)
    module = importlib.import_module(module_name)
    fn = getattr(module, fn_name, None)
    if fn is None or not callable(fn):
        raise CapabilityRunError(f"python callable not found: {spec}")
    return fn


@dataclass(frozen=True)
class ExecutionEngine:
    egress: EgressController | None = None

    def run(self, manifest: Dict[str, Any], args: Dict[str, Any]) -> Any:
        impl = manifest.get("implementation") or {}
        kind = impl.get("kind")
        if kind == "command":
            argv = (impl.get("command") or {}).get("argv") or []
            if not isinstance(argv, list) or not argv:
                raise CapabilityRunError("command.argv required")
            extra = args.get("argv_extra") or []
            if extra:
                if not isinstance(extra, list) or not all(isinstance(x, str) for x in extra):
                    raise CapabilityRunError("args.argv_extra must be a list of strings")
                argv = list(argv) + list(extra)
            timeout = min(float((manifest.get("runtime") or {}).get("timeout_seconds") or 30), 300.0)
            try:
                # Commands receive a deliberately minimal environment. Credentials are
                # injected by the broker at the transport edge, never inherited here.
                safe_env = {key: value for key, value in os.environ.items() if key in {"LANG", "LC_ALL", "TZ"}}
                proc = subprocess.run(  # nosec B603 - argv is a validated static list; shell is never enabled.
                    argv, capture_output=True, text=True, timeout=timeout, check=False,
                    shell=False, env=safe_env, close_fds=True,
                )
            except Exception as exc:
                raise CapabilityRunError(f"command execution failed: {exc}") from exc
            return {"returncode": proc.returncode, "stdout": proc.stdout, "stderr": proc.stderr}

        if kind == "python":
            callable_spec = (impl.get("python") or {}).get("callable")
            if not isinstance(callable_spec, str) or ":" not in callable_spec:
                raise CapabilityRunError("python.callable required")
            fn = _load_callable(callable_spec)
            try:
                params = list(inspect.signature(fn).parameters.values())
                if len(params) == 1:
                    return fn(args)
                if len(params) == 2:
                    return fn(manifest, args)
                raise CapabilityRunError("python callable must accept (args) or (manifest, args)")
            except Exception as exc:
                raise CapabilityRunError(f"python tool raised: {exc}") from exc

        if kind == "mcp_tool":
            mcp = impl.get("mcp") or {}
            registry_url = mcp.get("registry_url")
            tool_name = mcp.get("tool_name")
            server_id = mcp.get("server_id")
            if not registry_url or not tool_name:
                raise CapabilityRunError("mcp.registry_url and mcp.tool_name required")
            return self._run_mcp_tool(
                manifest,
                str(registry_url),
                str(tool_name),
                args,
                server_id=str(server_id) if server_id else None,
            )

        if kind == "a2a_rpc":
            a2a = impl.get("a2a") or {}
            endpoint = a2a.get("endpoint")
            if not endpoint:
                raise CapabilityRunError("a2a.endpoint required")
            return self._run_a2a(manifest, str(endpoint), args=args, capability_id=str(manifest.get("id")))

        raise CapabilityRunError(f"unsupported implementation.kind: {kind}")

    def _run_mcp_tool(
        self,
        manifest: Dict[str, Any],
        registry_url: str,
        tool_name: str,
        args: Dict[str, Any],
        *,
        server_id: Optional[str] = None,
    ) -> Any:
        enforce_manifest_network(manifest, registry_url)
        try:
            if self.egress:
                resp = self.egress.request("GET", registry_url, timeout=5.0)
            else:
                with httpx.Client(timeout=5.0) as client:
                    resp = client.get(registry_url)
            resp.raise_for_status()
            registry = resp.json()
        except Exception as exc:
            raise CapabilityRunError(f"mcp discovery failed: {exc}") from exc

        servers = registry if isinstance(registry, list) else registry.get("servers", []) if isinstance(registry, dict) else []
        for server in servers:
            sid = server.get("id") or server.get("name") or "mcp"
            if server_id and str(sid) != str(server_id):
                continue
            base = server.get("base_url") or server.get("url")
            if not base:
                continue
            tools = server.get("tools") or []
            if not any(isinstance(t, dict) and t.get("name") == tool_name for t in tools):
                continue
            try:
                call_url = f"{base}/tools/{tool_name}"
                enforce_manifest_network(manifest, call_url)
                if self.egress:
                    call_resp = self.egress.request("POST", call_url, json={"arguments": args}, timeout=10.0)
                else:
                    with httpx.Client(timeout=10.0) as client:
                        call_resp = client.post(call_url, json={"arguments": args})
                call_resp.raise_for_status()
                return call_resp.json()
            except Exception as exc:
                raise CapabilityRunError(f"mcp tool call failed: {exc}") from exc
        raise CapabilityRunError(f"mcp tool not found: {tool_name}")

    def _run_a2a(self, manifest: Dict[str, Any], endpoint: str, *, args: Dict[str, Any], capability_id: str) -> Any:
        enforce_manifest_network(manifest, endpoint)
        envelope = {
            "type": "a2a.request",
            "capability_id": capability_id,
            "args": args,
        }
        try:
            if self.egress:
                resp = self.egress.request("POST", endpoint, json=envelope, timeout=15.0)
            else:
                with httpx.Client(timeout=15.0) as client:
                    resp = client.post(endpoint, json=envelope)
            resp.raise_for_status()
            return resp.json()
        except Exception as exc:
            raise CapabilityRunError(f"a2a call failed: {exc}") from exc
