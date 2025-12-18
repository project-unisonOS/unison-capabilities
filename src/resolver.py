from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass
from typing import Any, Dict, List, Optional

import httpx
from urllib.parse import urlparse

from discovery import Candidate, RegistryAdapter, candidate_id_for, score_manifest
from errors import CapabilityInstallError, CapabilityManifestError, CapabilityNotFoundError
from egress import EgressController
from execution import ExecutionEngine
from installer import Installer
from locks import FileLock
from policy import CapabilityPolicy
from schema import validate_manifest
from store import CapabilityRef, CapabilityStore


def _normalize_digest(digest: str) -> str:
    d = digest.strip().lower()
    if d.startswith("sha256:"):
        d = d.split("sha256:", 1)[1]
    return d


def _sha256_text(data: str) -> str:
    return hashlib.sha256(data.encode("utf-8")).hexdigest()


@dataclass
class CapabilityResolver:
    store: CapabilityStore
    policy: CapabilityPolicy
    exec_engine: ExecutionEngine
    registries: List[RegistryAdapter] = None  # type: ignore[assignment]
    lock: Optional[FileLock] = None
    egress: Optional[EgressController] = None

    @classmethod
    def from_env(cls) -> "CapabilityResolver":
        store = CapabilityStore.from_env()
        return cls(
            store=store,
            policy=CapabilityPolicy.from_env(),
            exec_engine=ExecutionEngine(),
            registries=[],
            lock=FileLock(store.lock_path()),
            egress=None,
        )

    def _lock(self) -> FileLock:
        if self.lock is None:
            self.lock = FileLock(self.store.lock_path())
        return self.lock

    def list(self) -> List[Dict[str, Any]]:
        with self._lock().shared():
            out: List[Dict[str, Any]] = []
            for cid, m in sorted(self.store.merged_catalog().items()):
                out.append(
                    {
                        "id": m.get("id"),
                        "version": m.get("version"),
                        "type": m.get("type"),
                        "description": m.get("description"),
                        "trust_level": m.get("trust_level"),
                        "enabled": m.get("enabled", True),
                        "requires_oauth": m.get("requires_oauth", False),
                    }
                )
            return out

    def get(self, *, capability_id: str, version: Optional[str] = None) -> Dict[str, Any]:
        with self._lock().shared():
            merged = self.store.merged_catalog()
            if capability_id not in merged:
                raise CapabilityNotFoundError(f"capability not found: {capability_id}")
            m = merged[capability_id]
            if version and str(m.get("version")) != str(version):
                raise CapabilityNotFoundError(f"capability version not found: {capability_id}@{version}")
            return m

    def remove(self, *, capability_id: str, version: str) -> bool:
        with self._lock().exclusive():
            merged = self.store.merged_catalog()
            if capability_id not in merged:
                return False

            # If the capability is local (installed/overridden), delete it from local.
            removed_local = self.store.delete_local(capability_id=capability_id)
            if not removed_local:
                # Otherwise disable via local override (base remains immutable).
                self.store.set_local_enabled(capability_id=capability_id, enabled=False)

            # Best-effort cleanup of local artifacts for that version.
            try:
                self.store.remove(CapabilityRef(capability_id=capability_id, version=version))
            except Exception:
                pass
            return True

    def search(self, *, intent: str, constraints: Optional[Dict[str, Any]] = None) -> List[Candidate]:
        constraints = constraints or {}
        candidates: List[Candidate] = []

        # Effective (base + local) catalog.
        with self._lock().shared():
            for _, manifest in self.store.merged_catalog().items():
                base_score = score_manifest(intent, manifest)
                c = Candidate(
                    candidate_id=candidate_id_for(manifest, "catalog"),
                    manifest=manifest,
                    source="catalog",
                    score=base_score + (10.0 if base_score > 0 else 0.0),
                )
                candidates.append(c)

        # Registry adapters (installable candidates).
        for reg in self.registries or []:
            try:
                candidates.extend(reg.list(query=intent, filters=constraints))
            except Exception:
                continue

        # Apply basic constraints (trust allowlist override).
        allow_trust = constraints.get("trust_allow")
        if isinstance(allow_trust, list) and allow_trust:
            allow_set = {str(x) for x in allow_trust}
            candidates = [c for c in candidates if str(c.manifest.get("trust_level")) in allow_set]

        candidates.sort(key=lambda c: c.score, reverse=True)
        return candidates

    def _builtin_catalog(self, *, intent: str) -> List[Candidate]:
        """
        Minimal built-in catalog so planners can resolve "Intent → local tool" without
        inventing tools at runtime.
        """
        builtins = [
            {
                "id": "demo.echo",
                "type": "tool",
                "version": "0.1.0",
                "description": "Echo input text",
                "origin": {"source": "local", "digest": "sha256:" + "0" * 64, "path": "builtin"},
                "interfaces": {
                    "inputs": {"type": "object", "properties": {"text": {"type": "string"}}},
                    "outputs": {"type": "object", "properties": {"echo": {}}},
                },
                "permissions": {"network": "deny", "filesystem": "none", "devices": []},
                "runtime": {"sandbox": "process", "resources": {"cpu": "default", "memory": "default"}, "timeout_seconds": 5},
                "trust_level": "local",
                "execution": {"channel": "programmatic"},
                "implementation": {"kind": "python", "python": {"callable": "capability_builtins:echo"}},
            },
            {
                "id": "demo.time_now",
                "type": "tool",
                "version": "0.1.0",
                "description": "Return current UTC time",
                "origin": {"source": "local", "digest": "sha256:" + "0" * 64, "path": "builtin"},
                "interfaces": {"inputs": {"type": "object", "properties": {}}, "outputs": {"type": "object", "properties": {"iso": {}}}},
                "permissions": {"network": "deny", "filesystem": "none", "devices": []},
                "runtime": {"sandbox": "process", "resources": {"cpu": "default", "memory": "default"}, "timeout_seconds": 5},
                "trust_level": "local",
                "execution": {"channel": "programmatic"},
                "implementation": {"kind": "python", "python": {"callable": "capability_builtins:time_now"}},
            },
        ]
        out: List[Candidate] = []
        for m in builtins:
            validate_manifest(m)
            out.append(
                Candidate(
                    candidate_id=candidate_id_for(m, "builtin"),
                    manifest=m,
                    source="builtin",
                    score=score_manifest(intent, m),
                )
            )
        return out

    def resolve(self, *, step: Dict[str, Any]) -> Candidate:
        if not isinstance(step, dict):
            raise CapabilityManifestError("step must be an object")
        intent = str(step.get("intent") or "")
        constraints = step.get("constraints") if isinstance(step.get("constraints"), dict) else {}
        if not intent:
            raise CapabilityManifestError("step.intent required")

        candidates = self.search(intent=intent, constraints=constraints)
        if not candidates:
            raise CapabilityNotFoundError(f"no candidates found for intent: {intent}")

        # Prefer local catalog candidates; otherwise require policy-allowed installation.
        for c in candidates:
            if c.source == "catalog":
                return c
            try:
                self.policy.enforce_install(c.manifest)
                return c
            except Exception:
                continue
        raise CapabilityNotFoundError(f"no policy-allowed candidates for intent: {intent}")

    def install(self, *, candidate: Dict[str, Any]) -> Dict[str, Any]:
        with self._lock().exclusive():
            if not isinstance(candidate, dict) or not isinstance(candidate.get("manifest"), dict):
                raise CapabilityInstallError("candidate.manifest required")
            manifest = dict(candidate["manifest"])
            validate_manifest(manifest)
            self.policy.enforce_install(manifest)

            origin = manifest.get("origin") or {}
            source = origin.get("source")

            # Optional remote manifest fetch when the caller supplies an explicit `manifest_url`.
            # Digest pinning uses the canonical JSON form (sorted keys, compact separators).
            manifest_url = candidate.get("manifest_url")
            if source == "url" and isinstance(manifest_url, str) and manifest_url:
                if urlparse(manifest_url).scheme != "https":
                    raise CapabilityInstallError("remote manifest fetch requires https")
                try:
                    if self.egress:
                        resp = self.egress.request("GET", manifest_url, timeout=5.0)
                    else:
                        with httpx.Client(timeout=5.0) as client:
                            resp = client.get(manifest_url)
                    resp.raise_for_status()
                    remote = resp.json()
                except Exception as exc:
                    raise CapabilityInstallError(f"failed to fetch remote manifest from candidate.manifest_url: {exc}") from exc
                if not isinstance(remote, dict):
                    raise CapabilityInstallError("remote manifest must be an object")
                validate_manifest(remote)
                expected = _normalize_digest(str(manifest.get("origin", {}).get("digest") or ""))
                if expected:
                    canon = json.dumps(remote, sort_keys=True, separators=(",", ":"))
                    actual = _sha256_text(canon)
                    if actual != expected:
                        raise CapabilityInstallError(
                            "origin.digest pinning failed (sha256 of canonical manifest does not match)"
                        )
                manifest = remote

            installer = Installer(store=self.store)
            res = installer.install_manifest_atomic(manifest=manifest, meta={"installed_via": candidate.get("source")})

            # Persist to local catalog (writes always go to local).
            self.store.upsert_local(manifest)

            # Optional local payload copy for SKILL.md-style packs or local tooling bundles.
            origin_path = origin.get("path")
            if source == "local" and isinstance(origin_path, str) and origin_path:
                try:
                    self.store.put_payload_from_path(ref=res.ref, src_path=origin_path)
                except Exception:
                    pass

            return {"installed": {"id": res.ref.capability_id, "version": res.ref.version}}

    def run(self, *, capability_id: str, args: Dict[str, Any]) -> Any:
        with self._lock().shared():
            if not isinstance(args, dict):
                raise CapabilityManifestError("args must be an object")
            version = args.get("version")
            requested_channel = args.get("execution_channel") or args.get("requested_channel")
            if not requested_channel:
                # Backward-compatible fallback: treat `args.channel` as an execution channel
                # only when it matches the manifest's execution.channel enum.
                maybe = args.get("channel")
                if maybe in {"programmatic", "vdi_vpn"}:
                    requested_channel = maybe
            manifest = self.get(capability_id=capability_id, version=str(version) if version else None)
            self.policy.enforce_run(manifest, requested_channel=str(requested_channel) if requested_channel else None)
            return self.exec_engine.run(manifest, args)
