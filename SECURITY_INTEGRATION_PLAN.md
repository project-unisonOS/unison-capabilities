# Security Integration Plan (unison-capability)

This plan aligns `unison-capability` with existing UnisonOS security architecture and `unison-security` guidance.

## Sources (normative / referenced)
- `unison-security/docs/SERVICE_IDENTITY.md` (SPIFFE/SPIRE mTLS + Envoy sidecars + OPA `ext_authz`)
- `unison-security/docs/LOGGING_AUDIT_SCHEMA.md` and `unison-security/docs/LOGGING_GUIDE.md` (structured audit + redaction)
- `unison-common/src/unison_common/auth.py` (JWT/service token verification + RBAC helpers)
- `unison-docs/dev/storage-architecture-unification.md` (secrets in vault; references only elsewhere)
- Capability contract/spec:
  - `docs/platform/capabilities/03-planner-capability-contract.md`
  - `unison-docs/docs/platform/capabilities/planner-contract.md`

## Security posture (target)

### Network / identity
- Default runtime: **bind only to loopback** (`127.0.0.1`) or **UNIX domain socket**.
- Production deployment: run behind an **Envoy sidecar** with **SPIFFE mTLS** and optional **OPA ext_authz** (per `unison-security`), with the application listening on localhost only.

### Authentication
- Primary: **JWT/service token auth** using `unison-auth` with verification via `unison-common` helpers.
- Development fallback: optional static bearer token or explicit `unsafe` mode (off by default).

### Authorization
Separate privilege tiers (default):
- **Read**: `search`, `resolve`, `list`, `get`
- **Run**: `run`
- **Admin**: `install`, `remove`

Authorization uses existing Unison roles (`admin`, `operator`, `service`) and does **not** invent new global roles.
Where finer-grained separation is needed (e.g., allow the orchestrator service to install but not any service), use **service allowlists** (e.g., allowlisted `sub` values like `service-orchestrator`) configured in `unison-capability`, not new token semantics.

### Secrets
- Resolver never stores secret values.
- Manifests only contain secret references (`secrets[].ref`), consistent with platform docs.
- Audit logs and metrics MUST NOT log secret references verbatim when avoidable; log “present/absent” or redacted placeholders.
- OAuth onboarding stores refresh tokens in a secrets backend; the local manifest stores only `secret://...` handles (or `vault://...` in production).

### Supply-chain / integrity
- Installation flow must be atomic and fail-closed:
  - stage → validate (schema + policy) → verify digest/pinning (when applicable) → promote
  - no partial installs become runnable

## What lives in unison-capability vs delegated to unison-security

### Must live in `unison-capability`
- **Local binding defaults** and request-source restrictions (loopback/UDS by default).
- **API authentication + authorization** enforcement when called directly (especially in dev / without sidecars).
- **Atomic install + rollback**, store locking, and “never execute unvalidated manifests”.
- **Capability-level enforcement**:
  - `trust_level` allow/deny
  - execution channel enforcement (`execution.channel`)
  - permissions enforcement for outbound calls (network allowlist/deny; filesystem none/read/write)
- **Structured audit events** for capability actions (search/resolve/install/run/remove).
- A single **egress control point** for all outbound HTTP calls (MCP registry, remote manifest fetch, A2A).

### Should be delegated to `unison-security` (or its sidecars)
- **mTLS and service identity** enforcement (SPIFFE/SPIRE SVIDs via Envoy SDS).
- **Centralized policy** (OPA/Cedar) decisions for org-wide RBAC/ABAC and consent gating (via Envoy `ext_authz`).
- **Policy bundle build/sign/verification** and distribution.
- **Central audit forwarding** and log collection pipelines.

## Reuse plan (existing primitives)
- Use `unison-common` for:
  - JWT/service token verification
  - standardized structured logging with redaction (`log_json`)
  - optional request audit middleware (header redaction)
- Deploy behind `unison-security` Envoy/OPA templates for:
  - loopback-only backend binding
  - SPIFFE mTLS
  - `ext_authz` policy enforcement

## Gaps / required additions

### In unison-capability
- Implement loopback/UDS-only defaults and an explicit unsafe mode flag.
- Add RBAC gates per endpoint tier (read/run/admin) using existing roles and (optionally) service allowlists.
- Add transactional install pipeline with:
  - atomic file writes (`write temp → fsync → rename`)
  - staging directory + rollback
  - file locking for concurrent install/remove and safe reads
- Centralize outbound HTTP in a single egress module with:
  - global allow/deny lists
  - per-capability network allowlist enforcement
- Add `/healthz`, `/readyz`, `/version`, and `/metrics`.

### In unison-security (minimal / only if needed)
- Add a documented service identity entry for `unison-capability` (SPIFFE ID + sidecar template), if/when the core rollout includes it.
- Optionally extend policy bundles with capability-specific authorization rules (e.g., which service principals may `install`).
