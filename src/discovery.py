from __future__ import annotations

import hashlib
import json
import os
from dataclasses import dataclass
from pathlib import Path
from typing import Any, Dict, List, Optional, Protocol
from urllib.parse import urlparse

import httpx

from schema import validate_manifest


def _sha256_text(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Candidate:
    candidate_id: str
    manifest: Dict[str, Any]
    source: str
    score: float = 0.0
    manifest_url: Optional[str] = None


def candidate_id_for(manifest: Dict[str, Any], source: str) -> str:
    raw = json.dumps(manifest, sort_keys=True, separators=(",", ":"))
    h = _sha256_text(raw)
    return f"{manifest.get('id')}@{manifest.get('version')}:{source}:{h[:16]}"


def _trust_rank(level: str) -> int:
    order = {"verified": 0, "local": 1, "community": 2, "untrusted": 3}
    return order.get(level, 9)


def score_manifest(intent: str, manifest: Dict[str, Any]) -> float:
    desc = str(manifest.get("description") or "").lower()
    cap_id = str(manifest.get("id") or "").lower()
    intent_l = (intent or "").lower()
    s = 0.0
    if intent_l and intent_l in cap_id:
        s += 5.0
    if intent_l and intent_l in desc:
        s += 2.0
    s -= _trust_rank(str(manifest.get("trust_level") or "")) * 0.25
    return s


class RegistryAdapter(Protocol):
    name: str

    def list(self, *, query: str, filters: Optional[Dict[str, Any]] = None) -> List[Candidate]: ...
    def get(self, *, candidate_id: str) -> Candidate: ...
    def fetch(self, *, candidate_id: str) -> Dict[str, Any]: ...


@dataclass(frozen=True)
class StaticCatalogAdapter:
    name: str
    catalog_path: str

    def _load(self) -> List[Dict[str, Any]]:
        path = Path(self.catalog_path).expanduser().resolve()
        raw = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(raw, dict):
            items = raw.get("capabilities") or raw.get("items") or []
        else:
            items = raw
        if not isinstance(items, list):
            return []
        out: List[Dict[str, Any]] = []
        for m in items:
            if not isinstance(m, dict):
                continue
            validate_manifest(m)
            out.append(m)
        return out

    def list(self, *, query: str, filters: Optional[Dict[str, Any]] = None) -> List[Candidate]:
        candidates: List[Candidate] = []
        for m in self._load():
            candidates.append(
                Candidate(
                    candidate_id=candidate_id_for(m, self.name),
                    manifest=m,
                    source=self.name,
                    score=score_manifest(query, m),
                )
            )
        candidates.sort(key=lambda c: c.score, reverse=True)
        return candidates

    def get(self, *, candidate_id: str) -> Candidate:
        for c in self.list(query="", filters=None):
            if c.candidate_id == candidate_id:
                return c
        raise KeyError(candidate_id)

    def fetch(self, *, candidate_id: str) -> Dict[str, Any]:
        c = self.get(candidate_id=candidate_id)
        return {"manifest": c.manifest}


@dataclass(frozen=True)
class HttpCatalogAdapter:
    name: str
    catalog_urls: List[str]
    egress: Any

    def _require_tls(self, url: str) -> None:
        if urlparse(url).scheme != "https":
            raise ValueError("http catalog adapter requires https")

    def _load_url(self, url: str) -> Any:
        self._require_tls(url)
        resp = self.egress.request("GET", url, timeout=5.0)
        resp.raise_for_status()
        return resp.json()

    def list(self, *, query: str, filters: Optional[Dict[str, Any]] = None) -> List[Candidate]:
        candidates: List[Candidate] = []
        for url in self.catalog_urls:
            data = self._load_url(url)
            items = data.get("capabilities") if isinstance(data, dict) else data
            if not isinstance(items, list):
                continue
            for entry in items:
                if not isinstance(entry, dict):
                    continue
                manifest = entry.get("manifest") if isinstance(entry.get("manifest"), dict) else None
                manifest_url = entry.get("manifest_url")
                if manifest:
                    validate_manifest(manifest)
                    candidates.append(
                        Candidate(
                            candidate_id=candidate_id_for(manifest, self.name),
                            manifest=manifest,
                            source=self.name,
                            score=score_manifest(query, manifest) - 2.0,
                            manifest_url=None,
                        )
                    )
                elif isinstance(manifest_url, str) and manifest_url:
                    # Minimal candidate shell; install will fetch using candidate.manifest_url and pin by origin.digest.
                    m = entry.get("candidate_manifest")
                    if not isinstance(m, dict):
                        continue
                    validate_manifest(m)
                    candidates.append(
                        Candidate(
                            candidate_id=candidate_id_for(m, self.name),
                            manifest=m,
                            source=self.name,
                            score=score_manifest(query, m) - 3.0,
                            manifest_url=str(manifest_url),
                        )
                    )
        candidates.sort(key=lambda c: c.score, reverse=True)
        return candidates

    def get(self, *, candidate_id: str) -> Candidate:
        for c in self.list(query="", filters=None):
            if c.candidate_id == candidate_id:
                return c
        raise KeyError(candidate_id)

    def fetch(self, *, candidate_id: str) -> Dict[str, Any]:
        c = self.get(candidate_id=candidate_id)
        if c.manifest_url:
            return {"manifest_url": c.manifest_url, "manifest": c.manifest}
        return {"manifest": c.manifest}


@dataclass(frozen=True)
class McpRegistryAdapter:
    """
    Adapter for MCP registry discovery (tool surfaces).

    This is not a "trusted" registry; the resulting candidates should be treated
    as installable/untrusted unless policy elevates trust.
    """

    name: str
    registry_url: str
    egress: Any

    @classmethod
    def from_env(cls, *, egress: Any) -> Optional["McpRegistryAdapter"]:
        url = os.getenv("UNISON_MCP_REGISTRY_URL")
        if not url:
            return None
        return cls(name="mcp_registry", registry_url=url, egress=egress)

    def list(self, *, query: str, filters: Optional[Dict[str, Any]] = None) -> List[Candidate]:
        candidates: List[Candidate] = []
        resp = self.egress.request("GET", self.registry_url, timeout=3.0)
        resp.raise_for_status()
        payload = resp.json()
        servers = payload if isinstance(payload, list) else payload.get("servers", []) if isinstance(payload, dict) else []
        for server in servers:
            base = server.get("base_url") or server.get("url")
            server_id = server.get("id") or server.get("name") or "mcp"
            tools = server.get("tools") or []
            for tool in tools:
                name = tool.get("name")
                if not name:
                    continue
                manifest = {
                    "id": f"mcp.tool:{name}",
                    "type": "tool",
                    "version": "0.0.0",
                    "description": tool.get("description") or f"MCP tool {name}",
                    "origin": {"source": "url", "digest": _sha256_text(f"{self.registry_url}:{server_id}:{name}")},
                    "interfaces": {
                        "inputs": tool.get("parameters") or {"type": "object", "properties": {}},
                        "outputs": {"type": "object"},
                    },
                    "permissions": {
                        "network": "allowlist",
                        "network_allowlist": [x for x in [base, self.registry_url] if x],
                        "filesystem": "none",
                        "devices": [],
                    },
                    "runtime": {"sandbox": "process", "resources": {"cpu": "default", "memory": "default"}, "timeout_seconds": 30},
                    "trust_level": "untrusted",
                    "enabled": True,
                    "execution": {"channel": "programmatic"},
                    "implementation": {"kind": "mcp_tool", "mcp": {"registry_url": self.registry_url, "server_id": str(server_id), "tool_name": str(name)}},
                }
                validate_manifest(manifest)
                candidates.append(
                    Candidate(
                        candidate_id=candidate_id_for(manifest, self.name),
                        manifest=manifest,
                        source=self.name,
                        score=score_manifest(query, manifest) - 4.0,
                    )
                )
        candidates.sort(key=lambda c: c.score, reverse=True)
        return candidates

    def get(self, *, candidate_id: str) -> Candidate:
        for c in self.list(query="", filters=None):
            if c.candidate_id == candidate_id:
                return c
        raise KeyError(candidate_id)

    def fetch(self, *, candidate_id: str) -> Dict[str, Any]:
        c = self.get(candidate_id=candidate_id)
        return {"manifest": c.manifest}
