from __future__ import annotations

import logging
import time
from typing import Any, Dict, Optional

import uvicorn
from fastapi import Body, Depends, FastAPI, HTTPException, Request
from starlette.middleware.cors import CORSMiddleware

from config import ServiceConfig
from locks import FileLock
from discovery import HttpCatalogAdapter, McpRegistryAdapter, StaticCatalogAdapter
from egress import EgressController
from execution import ExecutionEngine
from policy import CapabilityPolicy
from resolver import CapabilityResolver
from security import LocalOnlyMiddleware, SecurityDeps
from audit import AuditEmitter
from oauth import default_oauth_manager

from errors import (
    CapabilityInstallError,
    CapabilityManifestError,
    CapabilityNotFoundError,
    CapabilityPolicyError,
    CapabilityRunError,
)


try:
    from unison_common.logging import configure_logging, log_json
    from unison_common.tracing_middleware import TracingMiddleware
    from unison_common.audit_middleware import AuditMiddleware
except Exception:  # pragma: no cover
    configure_logging = None
    log_json = None
    TracingMiddleware = None
    AuditMiddleware = None


_start_time = time.time()
_metrics: Dict[str, int] = {}
_latency_sum: Dict[str, float] = {}
_latency_count: Dict[str, int] = {}


def _http_error(exc: Exception) -> HTTPException:
    if isinstance(exc, CapabilityNotFoundError):
        return HTTPException(status_code=404, detail=str(exc))
    if isinstance(exc, (CapabilityManifestError, CapabilityPolicyError, CapabilityInstallError)):
        return HTTPException(status_code=400, detail=str(exc))
    if isinstance(exc, CapabilityRunError):
        return HTTPException(status_code=500, detail=str(exc))
    return HTTPException(status_code=500, detail=str(exc))

def _metric(name: str) -> None:
    _metrics[name] = _metrics.get(name, 0) + 1


def _observe(name: str, seconds: float) -> None:
    _latency_sum[name] = _latency_sum.get(name, 0.0) + float(seconds)
    _latency_count[name] = _latency_count.get(name, 0) + 1


def create_app(config: ServiceConfig, *, egress_controller: EgressController | None = None) -> FastAPI:
    if config.auth.mode == "disabled" and not config.auth.unsafe_allow_no_auth:
        raise RuntimeError("UNISON_CAPABILITY_AUTH_MODE=disabled requires UNISON_CAPABILITY_UNSAFE_NO_AUTH=true")

    app = FastAPI(title=config.service_name, version=config.version)

    # Safe default: loopback-only unless explicitly configured.
    app.add_middleware(LocalOnlyMiddleware, bind=config.bind)

    # Optional standard middlewares (if available via unison-common).
    if TracingMiddleware:
        app.add_middleware(TracingMiddleware, service_name=config.service_name)
    if AuditMiddleware:
        app.add_middleware(AuditMiddleware, service_name=config.service_name)

    # CORS: disabled by default for internal service surfaces.
    app.add_middleware(
        CORSMiddleware,
        allow_origins=[],
        allow_credentials=False,
        allow_methods=["GET", "POST", "DELETE"],
        allow_headers=["authorization", "content-type", "x-request-id", "x-event-id"],
    )

    from store import CapabilityStore

    store = CapabilityStore(base_dir=config.store.base_path())
    egress = egress_controller or EgressController(config.egress)
    registries = []
    if config.registries.static_catalog_path:
        registries.append(StaticCatalogAdapter(name="static_catalog", catalog_path=config.registries.static_catalog_path))
    if config.registries.http_catalog_urls:
        registries.append(HttpCatalogAdapter(name="http_catalog", catalog_urls=config.registries.http_catalog_urls, egress=egress))
    mcp = McpRegistryAdapter.from_env(egress=egress)
    if mcp:
        registries.append(mcp)
    resolver = CapabilityResolver(
        store=store,
        policy=CapabilityPolicy.from_env(),
        exec_engine=ExecutionEngine(egress=egress),
        registries=registries,
        lock=FileLock(store.lock_path()),
        egress=egress,
    )
    security = SecurityDeps.from_config(auth=config.auth, authz=config.authz)
    audit = AuditEmitter(service=config.service_name)

    def _request_id(request: Request) -> str | None:
        return request.headers.get("x-request-id") or request.headers.get("x-event-id")

    @app.get("/healthz")
    @app.get("/health")
    def healthz(request: Request) -> Dict[str, Any]:
        _metric("/healthz")
        return {"status": "ok", "service": config.service_name}

    @app.get("/readyz")
    @app.get("/ready")
    def readyz(request: Request) -> Dict[str, Any]:
        _metric("/readyz")
        ok = True
        detail: Dict[str, Any] = {}
        try:
            # Ensure store path is readable/writable and lock file is creatable.
            store.base_dir.mkdir(parents=True, exist_ok=True)
            lock = FileLock(store.lock_path())
            with lock.shared():
                pass
            detail["store_dir"] = str(store.base_dir)
        except Exception as exc:
            ok = False
            detail["store_error"] = str(exc)

        try:
            from schema import load_manifest_validator

            load_manifest_validator()
            detail["schema"] = config.schema_version
        except Exception as exc:
            ok = False
            detail["schema_error"] = str(exc)

        try:
            base_path = store.base_catalog()
            if not base_path.exists():
                ok = False
                detail["base_catalog_error"] = f"missing base catalog: {base_path}"
            else:
                _ = store.load_base_catalog()
                detail["base_catalog"] = str(base_path)
        except Exception as exc:
            ok = False
            detail["base_catalog_error"] = str(exc)

        return {"ready": ok, **detail}

    @app.get("/version")
    def version() -> Dict[str, Any]:
        _metric("/version")
        return {"service": config.service_name, "version": config.version, "schema_version": config.schema_version}

    @app.get("/metrics")
    def metrics() -> str:
        _metric("/metrics")
        uptime = time.time() - _start_time
        lines = [
            "# HELP unison_capability_requests_total Total number of requests by endpoint",
            "# TYPE unison_capability_requests_total counter",
        ]
        for k, v in sorted(_metrics.items()):
            lines.append(f'unison_capability_requests_total{{endpoint="{k}"}} {v}')
        lines.extend(
            [
                "",
                "# HELP unison_capability_latency_seconds_sum Total latency by operation",
                "# TYPE unison_capability_latency_seconds_sum counter",
            ]
        )
        for k, v in sorted(_latency_sum.items()):
            lines.append(f'unison_capability_latency_seconds_sum{{op="{k}"}} {v}')
        lines.extend(
            [
                "",
                "# HELP unison_capability_latency_seconds_count Total latency samples by operation",
                "# TYPE unison_capability_latency_seconds_count counter",
            ]
        )
        for k, v in sorted(_latency_count.items()):
            lines.append(f'unison_capability_latency_seconds_count{{op="{k}"}} {v}')
        lines.extend(
            [
                "",
                "# HELP unison_capability_uptime_seconds Service uptime in seconds",
                "# TYPE unison_capability_uptime_seconds gauge",
                f"unison_capability_uptime_seconds {uptime}",
            ]
        )
        return "\n".join(lines)

    @app.post("/capability/search")
    def capability_search(
        request: Request,
        payload: Dict[str, Any] = Body(...),
        user: Dict[str, Any] = Depends(security.read),
    ) -> Dict[str, Any]:
        _metric("/capability/search")
        t0 = time.perf_counter()
        try:
            intent = str(payload.get("intent") or "")
            constraints = payload.get("constraints") if isinstance(payload.get("constraints"), dict) else {}
            if not intent:
                raise CapabilityManifestError("intent required")
            if resolver.registries:
                audit.emit(
                    event="registry.fetch",
                    principal=user,
                    request_id=_request_id(request),
                    outcome="allow",
                    resource_type="registry",
                    resource_id="catalogs",
                )
            audit.emit(
                event="capability.search",
                principal=user,
                request_id=_request_id(request),
                outcome="allow",
                resource_type="intent",
                resource_id=intent,
            )
            candidates = resolver.search(intent=intent, constraints=constraints)
            return {
                "candidates": [
                    {
                        "candidate_id": c.candidate_id,
                        "source": c.source,
                        "score": c.score,
                        "manifest": c.manifest,
                        **({"manifest_url": c.manifest_url} if getattr(c, "manifest_url", None) else {}),
                    }
                    for c in candidates
                ]
            }
        except Exception as exc:
            audit.emit(
                event="capability.search",
                principal=user,
                request_id=_request_id(request),
                outcome="error",
                reason=str(exc),
                resource_type="intent",
                resource_id=str(payload.get("intent") or ""),
                severity="ERROR",
            )
            raise _http_error(exc)
        finally:
            _observe("search", time.perf_counter() - t0)

    @app.post("/capability/resolve")
    def capability_resolve(
        request: Request,
        payload: Dict[str, Any] = Body(...),
        user: Dict[str, Any] = Depends(security.read),
    ) -> Dict[str, Any]:
        _metric("/capability/resolve")
        t0 = time.perf_counter()
        try:
            step = payload.get("step")
            if not isinstance(step, dict):
                raise CapabilityManifestError("step required")
            audit.emit(
                event="capability.resolve",
                principal=user,
                request_id=_request_id(request),
                outcome="allow",
                resource_type="intent",
                resource_id=str(step.get("intent") or ""),
            )
            c = resolver.resolve(step=step)
            out = {"candidate_id": c.candidate_id, "source": c.source, "score": c.score, "manifest": c.manifest}
            if getattr(c, "manifest_url", None):
                out["manifest_url"] = c.manifest_url
            return {"candidate": out}
        except Exception as exc:
            audit.emit(
                event="capability.resolve",
                principal=user,
                request_id=_request_id(request),
                outcome="error",
                reason=str(exc),
                resource_type="intent",
                resource_id=str(step.get("intent") or "") if isinstance(step, dict) else "",
                severity="ERROR",
            )
            raise _http_error(exc)
        finally:
            _observe("resolve", time.perf_counter() - t0)

    @app.post("/capability/install")
    def capability_install(
        request: Request,
        payload: Dict[str, Any] = Body(...),
        user: Dict[str, Any] = Depends(security.admin_install),
    ) -> Dict[str, Any]:
        _metric("/capability/install")
        t0 = time.perf_counter()
        try:
            candidate = payload.get("candidate")
            if not isinstance(candidate, dict):
                raise CapabilityInstallError("candidate required")
            m = candidate.get("manifest") if isinstance(candidate.get("manifest"), dict) else {}
            audit.emit(
                event="capability.install_start",
                principal=user,
                request_id=_request_id(request),
                outcome="allow",
                resource_type="capability",
                resource_id=str(m.get("id") or ""),
            )
            return resolver.install(candidate=candidate)
        except Exception as exc:
            audit.emit(
                event="capability.install_failure",
                principal=user,
                request_id=_request_id(request),
                outcome="error",
                reason=str(exc),
                resource_type="capability",
                resource_id=str((candidate or {}).get("manifest", {}).get("id") if isinstance(candidate, dict) else ""),
                severity="ERROR",
            )
            raise _http_error(exc)
        finally:
            _observe("install", time.perf_counter() - t0)

    @app.post("/capability/run")
    def capability_run(
        request: Request,
        payload: Dict[str, Any] = Body(...),
        user: Dict[str, Any] = Depends(security.run),
    ) -> Dict[str, Any]:
        _metric("/capability/run")
        t0 = time.perf_counter()
        try:
            capability_id = payload.get("capability_id")
            args = payload.get("args") if isinstance(payload.get("args"), dict) else {}
            if not capability_id:
                raise CapabilityManifestError("capability_id required")
            audit.emit(
                event="capability.run_start",
                principal=user,
                request_id=_request_id(request),
                outcome="allow",
                resource_type="capability",
                resource_id=str(capability_id),
            )
            result = resolver.run(capability_id=str(capability_id), args=args)
            return {"result": result}
        except Exception as exc:
            audit.emit(
                event="capability.run_failure",
                principal=user,
                request_id=_request_id(request),
                outcome="error",
                reason=str(exc),
                resource_type="capability",
                resource_id=str(payload.get("capability_id") or ""),
                severity="ERROR",
            )
            raise _http_error(exc)
        finally:
            _observe("run", time.perf_counter() - t0)

    @app.get("/capability/list")
    def capability_list(request: Request, user: Dict[str, Any] = Depends(security.read)) -> Dict[str, Any]:
        _metric("/capability/list")
        t0 = time.perf_counter()
        try:
            audit.emit(
                event="capability.list",
                principal=user,
                request_id=_request_id(request),
                outcome="allow",
                resource_type="capability",
                resource_id="list",
            )
            return {"items": resolver.list()}
        except Exception as exc:
            audit.emit(
                event="capability.list",
                principal=user,
                request_id=_request_id(request),
                outcome="error",
                reason=str(exc),
                severity="ERROR",
            )
            raise _http_error(exc)
        finally:
            _observe("list", time.perf_counter() - t0)

    @app.get("/capability/get/{capability_id}")
    def capability_get(
        request: Request,
        capability_id: str,
        version: Optional[str] = None,
        user: Dict[str, Any] = Depends(security.read),
    ) -> Dict[str, Any]:
        _metric("/capability/get")
        t0 = time.perf_counter()
        try:
            audit.emit(
                event="capability.get",
                principal=user,
                request_id=_request_id(request),
                outcome="allow",
                resource_type="capability",
                resource_id=capability_id,
            )
            return {"manifest": resolver.get(capability_id=capability_id, version=version)}
        except Exception as exc:
            audit.emit(
                event="capability.get",
                principal=user,
                request_id=_request_id(request),
                outcome="error",
                reason=str(exc),
                resource_type="capability",
                resource_id=capability_id,
                severity="ERROR",
            )
            raise _http_error(exc)
        finally:
            _observe("get", time.perf_counter() - t0)

    @app.delete("/capability/remove/{capability_id}")
    def capability_remove(
        request: Request,
        capability_id: str,
        version: str,
        user: Dict[str, Any] = Depends(security.admin_remove),
    ) -> Dict[str, Any]:
        _metric("/capability/remove")
        t0 = time.perf_counter()
        try:
            if not version:
                raise CapabilityManifestError("version required")
            ok = resolver.remove(capability_id=capability_id, version=version)
            audit.emit(
                event="capability.remove",
                principal=user,
                request_id=_request_id(request),
                outcome="allow",
                resource_type="capability",
                resource_id=f"{capability_id}@{version}",
            )
            return {"removed": ok}
        except Exception as exc:
            audit.emit(
                event="capability.remove",
                principal=user,
                request_id=_request_id(request),
                outcome="error",
                reason=str(exc),
                resource_type="capability",
                resource_id=f"{capability_id}@{version}",
                severity="ERROR",
            )
            raise _http_error(exc)
        finally:
            _observe("remove", time.perf_counter() - t0)

    @app.post("/capability/oauth/start")
    def oauth_start(
        request: Request,
        payload: Dict[str, Any] = Body(...),
        user: Dict[str, Any] = Depends(security.admin_install),
    ) -> Dict[str, Any]:
        _metric("/capability/oauth/start")
        capability_id = payload.get("capability_id")
        if not isinstance(capability_id, str) or not capability_id:
            raise HTTPException(status_code=400, detail="capability_id required")
        try:
            oauth_mgr = default_oauth_manager(store=store, egress=egress)
            out = oauth_mgr.start(capability_id=capability_id, principal=user, audit=audit)
            return out
        except Exception as exc:
            audit.emit(event="oauth.start", principal=user, request_id=_request_id(request), outcome="error", reason=str(exc), severity="ERROR")
            raise _http_error(exc)

    @app.post("/capability/oauth/complete")
    def oauth_complete(
        request: Request,
        payload: Dict[str, Any] = Body(...),
        user: Dict[str, Any] = Depends(security.admin_install),
    ) -> Dict[str, Any]:
        _metric("/capability/oauth/complete")
        session_id = payload.get("session_id")
        if not isinstance(session_id, str) or not session_id:
            raise HTTPException(status_code=400, detail="session_id required")
        try:
            oauth_mgr = default_oauth_manager(store=store, egress=egress)
            out = oauth_mgr.complete(session_id=session_id, principal=user, audit=audit)
            return out
        except Exception as exc:
            audit.emit(event="oauth.complete", principal=user, request_id=_request_id(request), outcome="error", reason=str(exc), severity="ERROR")
            raise _http_error(exc)

    @app.post("/capability/factory_reset")
    def factory_reset(
        request: Request,
        user: Dict[str, Any] = Depends(security.admin_remove),
    ) -> Dict[str, Any]:
        _metric("/capability/factory_reset")
        try:
            with resolver._lock().exclusive():  # store-level lock
                store.factory_reset()
            audit.emit(event="capability.factory_reset", principal=user, request_id=_request_id(request), outcome="allow")
            return {"status": "ok"}
        except Exception as exc:
            audit.emit(event="capability.factory_reset", principal=user, request_id=_request_id(request), outcome="error", reason=str(exc), severity="ERROR")
            raise _http_error(exc)

    return app


CONFIG = ServiceConfig.load()
app = create_app(CONFIG)


def main() -> None:
    cfg = ServiceConfig.load()
    if cfg.bind.uds_path:
        uvicorn.run("server:app", uds=cfg.bind.uds_path, host=None, port=None, log_level="info")
    else:
        uvicorn.run("server:app", host=cfg.bind.host, port=cfg.bind.port, log_level="info")


if __name__ == "__main__":
    main()
