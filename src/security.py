from __future__ import annotations

from dataclasses import dataclass
import os
from typing import Any, Callable, Dict, List, Optional

from fastapi import Depends, HTTPException, Request, status
from fastapi.security import HTTPAuthorizationCredentials, HTTPBearer
from starlette.middleware.base import BaseHTTPMiddleware

from config import AuthConfig, AuthzConfig, BindConfig

try:
    from unison_common.auth import verify_service_token, verify_token
    from unison_common.auth import verify_token_with_auth_service
    from unison_common.principal import principal_context_from_claims
except Exception:  # pragma: no cover
    verify_service_token = None
    verify_token = None
    verify_token_with_auth_service = None
    principal_context_from_claims = None


_http_bearer = HTTPBearer(auto_error=False)


class LocalOnlyMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, *, bind: BindConfig) -> None:
        super().__init__(app)
        self._bind = bind

    async def dispatch(self, request: Request, call_next):
        if self._bind.unsafe_allow_nonlocal:
            return await call_next(request)
        client = request.client
        if client is None:
            return await call_next(request)
        host = client.host
        if host in {"127.0.0.1", "::1", "testclient", "testserver"}:
            return await call_next(request)
        raise HTTPException(status_code=403, detail="non-local access denied")


async def _static_bearer_auth(auth: AuthConfig, credentials: Optional[HTTPAuthorizationCredentials]) -> Dict[str, Any]:
    if os.getenv("ENVIRONMENT", "development").lower() in {"prod", "production"}:
        raise HTTPException(status_code=500, detail="static bearer authentication is forbidden in production")
    if not credentials or credentials.scheme.lower() != "bearer":
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="authentication required")
    if not auth.static_bearer_token:
        raise HTTPException(status_code=500, detail="static bearer token mode enabled but no token configured")
    if credentials.credentials != auth.static_bearer_token:
        raise HTTPException(status_code=status.HTTP_401_UNAUTHORIZED, detail="invalid token")
    return {"username": "static-bearer", "roles": ["service"], "token_type": "service", "exp": None}


def make_auth_dependency(auth: AuthConfig) -> Callable[..., Any]:
    async def dep(request: Request, credentials: Optional[HTTPAuthorizationCredentials] = Depends(_http_bearer)) -> Dict[str, Any]:
        if auth.mode == "disabled":
            if not auth.unsafe_allow_no_auth:
                raise HTTPException(status_code=500, detail="auth disabled but unsafe flag not set")
            return {"username": "unauthenticated", "roles": ["service"], "token_type": "service", "exp": None}

        if auth.mode == "static_bearer":
            return await _static_bearer_auth(auth, credentials)

        if auth.mode == "unison_jwt":
            if verify_token is None or verify_token_with_auth_service is None or principal_context_from_claims is None:
                raise HTTPException(status_code=500, detail="unison-common not available for jwt verification")
            claims = await verify_token(credentials)
            active = await verify_token_with_auth_service(credentials.credentials)
            if not active or not active.get("valid"):
                raise HTTPException(status_code=401, detail="principal session is inactive")
            claims = dict(active.get("claims") or claims)
            try:
                context = principal_context_from_claims(claims, expected_audience="capability")
            except ValueError as exc:
                raise HTTPException(status_code=403, detail="principal audience or binding is invalid") from exc
            request.state.principal_context = context
            return {
                "username": context.login_handle or context.principal_id,
                "principal_id": context.principal_id,
                "person_id": context.person_id,
                "roles": list(context.roles),
                "token_type": claims.get("type"),
                "exp": context.expires_at,
            }

        raise HTTPException(status_code=500, detail=f"unsupported auth mode: {auth.mode}")

    return dep


def _deny(detail: str) -> HTTPException:
    return HTTPException(status_code=status.HTTP_403_FORBIDDEN, detail=detail)


def make_authz_dependency(
    *,
    authz: AuthzConfig,
    tier: str,
    authn_dep: Callable[..., Any],
) -> Callable[..., Any]:
    if tier not in {"read", "run", "admin_install", "admin_remove"}:
        raise ValueError(f"unknown tier: {tier}")

    roles_required = {
        "read": authz.read_roles,
        "run": authz.run_roles,
        "admin_install": authz.admin_roles,
        "admin_remove": authz.admin_roles,
    }[tier]

    allowed_services = {
        "admin_install": authz.install_allowed_services,
        "admin_remove": authz.remove_allowed_services,
    }.get(tier)

    async def dep(user: Dict[str, Any] = Depends(authn_dep)) -> Dict[str, Any]:
        user_roles = [str(x) for x in (user.get("roles") or [])]
        username = str(user.get("username") or "")

        if any(r in user_roles for r in roles_required):
            return user

        if allowed_services and username and username in set(allowed_services):
            return user

        raise _deny(f"insufficient permissions for {tier}")

    return dep


@dataclass(frozen=True)
class SecurityDeps:
    authn: Callable[..., Any]
    read: Callable[..., Any]
    run: Callable[..., Any]
    admin_install: Callable[..., Any]
    admin_remove: Callable[..., Any]

    @classmethod
    def from_config(cls, *, auth: AuthConfig, authz: AuthzConfig) -> "SecurityDeps":
        authn = make_auth_dependency(auth)
        return cls(
            authn=authn,
            read=make_authz_dependency(authz=authz, tier="read", authn_dep=authn),
            run=make_authz_dependency(authz=authz, tier="run", authn_dep=authn),
            admin_install=make_authz_dependency(authz=authz, tier="admin_install", authn_dep=authn),
            admin_remove=make_authz_dependency(authz=authz, tier="admin_remove", authn_dep=authn),
        )
