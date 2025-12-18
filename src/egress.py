from __future__ import annotations

import ipaddress
from dataclasses import dataclass, field
from typing import Any, Dict, Iterable, Optional
from urllib.parse import urlparse

import httpx

from config import EgressConfig
from errors import CapabilityPolicyError


def _is_private_or_loopback(host: str) -> bool:
    if host in {"localhost"}:
        return True
    try:
        ip = ipaddress.ip_address(host)
        return ip.is_loopback or ip.is_private or ip.is_link_local
    except ValueError:
        return False


def _host_matches(rule: str, host: str) -> bool:
    rule = rule.strip().lower()
    host = host.strip().lower()
    if not rule or not host:
        return False
    if rule.startswith("*.") and host.endswith(rule[1:]):
        return True
    if host == rule:
        return True
    return host.endswith("." + rule)


def _url_prefix_matches(prefix: str, url: str) -> bool:
    return url.lower().startswith(prefix.strip().lower())


@dataclass(frozen=True)
class EgressController:
    cfg: EgressConfig
    transport: httpx.BaseTransport | None = None

    def check_url(self, url: str) -> None:
        parsed = urlparse(url)
        if parsed.scheme not in {"http", "https"}:
            raise CapabilityPolicyError(f"egress denied: unsupported scheme: {parsed.scheme}")
        host = parsed.hostname or ""
        if not host:
            raise CapabilityPolicyError("egress denied: missing hostname")

        # Loopback is always allowed (service is expected to run behind local sidecars).
        if _is_private_or_loopback(host) and host in {"127.0.0.1", "::1", "localhost"}:
            return

        if _is_private_or_loopback(host) and not self.cfg.allow_private_networks:
            raise CapabilityPolicyError("egress denied: private network destinations require allow_private_networks=true")

        # Denylist takes precedence.
        for rule in self.cfg.denylist:
            if "://" in rule and _url_prefix_matches(rule, url):
                raise CapabilityPolicyError(f"egress denied by denylist: {rule}")
            if "://" not in rule and _host_matches(rule, host):
                raise CapabilityPolicyError(f"egress denied by denylist: {rule}")

        # Safe default: deny all non-loopback egress unless allowlisted.
        if not self.cfg.allowlist:
            raise CapabilityPolicyError("egress denied: no allowlist configured")

        for rule in self.cfg.allowlist:
            if "://" in rule and _url_prefix_matches(rule, url):
                return
            if "://" not in rule and _host_matches(rule, host):
                return
        raise CapabilityPolicyError("egress denied: destination not in allowlist")

    def request(
        self,
        method: str,
        url: str,
        *,
        json: Optional[Dict[str, Any]] = None,
        data: Optional[Dict[str, Any]] = None,
        headers: Optional[Dict[str, str]] = None,
        timeout: float = 5.0,
    ) -> httpx.Response:
        self.check_url(url)
        with httpx.Client(timeout=timeout, transport=self.transport) as client:
            return client.request(method, url, json=json, data=data, headers=headers)


def enforce_manifest_network(manifest: Dict[str, Any], url: str) -> None:
    perms = manifest.get("permissions") if isinstance(manifest.get("permissions"), dict) else {}
    mode = str(perms.get("network") or "deny")
    if mode == "deny":
        raise CapabilityPolicyError("network denied by capability permissions")
    if mode != "allowlist":
        raise CapabilityPolicyError(f"invalid permissions.network: {mode}")
    allow = perms.get("network_allowlist") if isinstance(perms.get("network_allowlist"), list) else []
    if not allow:
        raise CapabilityPolicyError("network allowlist required when permissions.network=allowlist")
    parsed = urlparse(url)
    host = parsed.hostname or ""
    for rule in allow:
        r = str(rule)
        if "://" in r and _url_prefix_matches(r, url):
            return
        if "://" not in r and _host_matches(r, host):
            return
    raise CapabilityPolicyError("egress denied: destination not permitted by capability network_allowlist")
