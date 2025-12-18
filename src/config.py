from __future__ import annotations

import os
from dataclasses import dataclass, field
from pathlib import Path
from typing import List, Optional

import yaml


def _split_csv(value: str) -> list[str]:
    return [x.strip() for x in value.split(",") if x.strip()]


@dataclass(frozen=True)
class AuthzConfig:
    read_roles: List[str] = field(default_factory=lambda: ["service", "operator", "admin"])
    run_roles: List[str] = field(default_factory=lambda: ["service", "operator", "admin"])
    admin_roles: List[str] = field(default_factory=lambda: ["operator", "admin"])
    install_allowed_services: List[str] = field(default_factory=lambda: ["service-orchestrator"])
    remove_allowed_services: List[str] = field(default_factory=lambda: ["service-orchestrator"])


@dataclass(frozen=True)
class AuthConfig:
    mode: str = "unison_jwt"  # unison_jwt | static_bearer | disabled
    static_bearer_token: Optional[str] = None
    unsafe_allow_no_auth: bool = False


@dataclass(frozen=True)
class BindConfig:
    host: str = "127.0.0.1"
    port: int = 8102
    uds_path: Optional[str] = None
    unsafe_allow_nonlocal: bool = False


@dataclass(frozen=True)
class StoreConfig:
    base_dir: str = "/var/lib/unison/capabilities"

    def base_path(self) -> Path:
        return Path(self.base_dir).expanduser().resolve()

    def tmp_path(self) -> Path:
        return self.base_path() / "tmp"

    def locks_path(self) -> Path:
        return self.base_path() / "locks"

    def logs_path(self) -> Path:
        return self.base_path() / "logs"

    def cache_path(self) -> Path:
        return self.base_path() / "cache"


@dataclass(frozen=True)
class EgressConfig:
    allowlist: List[str] = field(default_factory=list)
    denylist: List[str] = field(default_factory=list)
    allow_private_networks: bool = False


@dataclass(frozen=True)
class RegistriesConfig:
    static_catalog_path: Optional[str] = None
    http_catalog_urls: List[str] = field(default_factory=list)


@dataclass(frozen=True)
class ServiceConfig:
    service_name: str = "unison-capability"
    version: str = "0.1.0"
    schema_version: str = "capability.manifest.v0.1"

    bind: BindConfig = field(default_factory=BindConfig)
    auth: AuthConfig = field(default_factory=AuthConfig)
    authz: AuthzConfig = field(default_factory=AuthzConfig)
    store: StoreConfig = field(default_factory=StoreConfig)
    egress: EgressConfig = field(default_factory=EgressConfig)
    registries: RegistriesConfig = field(default_factory=RegistriesConfig)

    @classmethod
    def load(cls) -> "ServiceConfig":
        path = os.getenv("UNISON_CAPABILITY_CONFIG")
        if not path:
            # Conventional locations for service configs.
            for candidate in ("/etc/unison/unison-capability.yaml", "/etc/unison/unison-capability.yml"):
                if Path(candidate).exists():
                    path = candidate
                    break
        data = {}
        if path:
            data = yaml.safe_load(Path(path).read_text(encoding="utf-8")) or {}
        if not isinstance(data, dict):
            data = {}

        # Env overrides (safe defaults retained).
        store_dir = os.getenv("UNISON_CAPABILITY_STORE_DIR") or os.getenv("UNISON_CAPABILITY_STORE_BASE")
        if store_dir:
            data.setdefault("store", {})
            data["store"]["base_dir"] = store_dir

        auth_mode = os.getenv("UNISON_CAPABILITY_AUTH_MODE")
        if auth_mode:
            data.setdefault("auth", {})
            data["auth"]["mode"] = auth_mode
        token = os.getenv("UNISON_CAPABILITY_BEARER_TOKEN")
        if token:
            data.setdefault("auth", {})
            data["auth"]["static_bearer_token"] = token
        if (os.getenv("UNISON_CAPABILITY_UNSAFE_NO_AUTH") or "").lower() in {"1", "true", "yes", "on"}:
            data.setdefault("auth", {})
            data["auth"]["unsafe_allow_no_auth"] = True

        unsafe_nonlocal = os.getenv("UNISON_CAPABILITY_UNSAFE_ALLOW_NONLOCAL")
        if unsafe_nonlocal:
            data.setdefault("bind", {})
            data["bind"]["unsafe_allow_nonlocal"] = (unsafe_nonlocal or "").lower() in {"1", "true", "yes", "on"}
        host = os.getenv("UNISON_CAPABILITY_HOST")
        if host:
            data.setdefault("bind", {})
            data["bind"]["host"] = host
        port = os.getenv("UNISON_CAPABILITY_PORT")
        if port:
            data.setdefault("bind", {})
            data["bind"]["port"] = int(port)
        uds = os.getenv("UNISON_CAPABILITY_UDS")
        if uds:
            data.setdefault("bind", {})
            data["bind"]["uds_path"] = uds

        egress_allowlist = os.getenv("UNISON_CAPABILITY_EGRESS_ALLOWLIST")
        if egress_allowlist:
            data.setdefault("egress", {})
            data["egress"]["allowlist"] = egress_allowlist
        egress_denylist = os.getenv("UNISON_CAPABILITY_EGRESS_DENYLIST")
        if egress_denylist:
            data.setdefault("egress", {})
            data["egress"]["denylist"] = egress_denylist
        allow_private = os.getenv("UNISON_CAPABILITY_EGRESS_ALLOW_PRIVATE_NETWORKS")
        if allow_private:
            data.setdefault("egress", {})
            data["egress"]["allow_private_networks"] = (allow_private or "").lower() in {"1", "true", "yes", "on"}

        def _build_bind(d: dict) -> BindConfig:
            return BindConfig(
                host=str(d.get("host") or "127.0.0.1"),
                port=int(d.get("port") or 8102),
                uds_path=str(d.get("uds_path")) if d.get("uds_path") else None,
                unsafe_allow_nonlocal=bool(d.get("unsafe_allow_nonlocal") or False),
            )

        def _build_auth(d: dict) -> AuthConfig:
            return AuthConfig(
                mode=str(d.get("mode") or "unison_jwt"),
                static_bearer_token=str(d.get("static_bearer_token")) if d.get("static_bearer_token") else None,
                unsafe_allow_no_auth=bool(d.get("unsafe_allow_no_auth") or False),
            )

        def _build_authz(d: dict) -> AuthzConfig:
            return AuthzConfig(
                read_roles=list(d.get("read_roles") or AuthzConfig().read_roles),
                run_roles=list(d.get("run_roles") or AuthzConfig().run_roles),
                admin_roles=list(d.get("admin_roles") or AuthzConfig().admin_roles),
                install_allowed_services=list(d.get("install_allowed_services") or AuthzConfig().install_allowed_services),
                remove_allowed_services=list(d.get("remove_allowed_services") or AuthzConfig().remove_allowed_services),
            )

        def _build_store(d: dict) -> StoreConfig:
            return StoreConfig(base_dir=str(d.get("base_dir") or StoreConfig().base_dir))

        def _build_egress(d: dict) -> EgressConfig:
            allowlist = d.get("allowlist")
            denylist = d.get("denylist")
            return EgressConfig(
                allowlist=[str(x) for x in (allowlist or [])] if isinstance(allowlist, list) else _split_csv(str(allowlist or "")) if allowlist else [],
                denylist=[str(x) for x in (denylist or [])] if isinstance(denylist, list) else _split_csv(str(denylist or "")) if denylist else [],
                allow_private_networks=bool(d.get("allow_private_networks") or False),
            )

        def _build_registries(d: dict) -> RegistriesConfig:
            http_urls = d.get("http_catalog_urls") or d.get("http_catalogs") or []
            if isinstance(http_urls, str):
                http_urls = _split_csv(http_urls)
            if not isinstance(http_urls, list):
                http_urls = []
            return RegistriesConfig(
                static_catalog_path=str(d.get("static_catalog_path")) if d.get("static_catalog_path") else None,
                http_catalog_urls=[str(x) for x in http_urls if str(x).strip()],
            )

        return cls(
            service_name=str(data.get("service_name") or "unison-capability"),
            version=str(data.get("version") or "0.1.0"),
            schema_version=str(data.get("schema_version") or "capability.manifest.v0.1"),
            bind=_build_bind(data.get("bind") if isinstance(data.get("bind"), dict) else {}),
            auth=_build_auth(data.get("auth") if isinstance(data.get("auth"), dict) else {}),
            authz=_build_authz(data.get("authz") if isinstance(data.get("authz"), dict) else {}),
            store=_build_store(data.get("store") if isinstance(data.get("store"), dict) else {}),
            egress=_build_egress(data.get("egress") if isinstance(data.get("egress"), dict) else {}),
            registries=_build_registries(data.get("registries") if isinstance(data.get("registries"), dict) else {}),
        )
