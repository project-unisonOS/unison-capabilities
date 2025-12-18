# unison-capability status

## What changed (this iteration)
- Seeded capabilities system:
  - Layered catalogs: base (`manifests/manifest.base.json`) + local (`${store}/manifest.local.json`) with local override precedence (`src/store.py`).
  - Curated baseline catalog plus skill packs and connector placeholders (`manifests/manifest.base.json`, `skill_packs/*`).
  - Registry adapter framework (static + HTTPS catalog + MCP registry adapter) (`src/discovery.py`, `src/server.py`, `registries/static_catalog.json`).
  - OAuth device-flow onboarding and encrypted secrets backend (`src/oauth.py`, `src/secrets.py`), secrets referenced by `secret://...` handles only.
- Security-first API surface:
  - Loopback/UDS-only posture via `LocalOnlyMiddleware` (`src/security.py`) with explicit unsafe override.
  - Authn modes: `unison_jwt` (preferred), `static_bearer` (dev fallback), `disabled` (unsafe, off by default).
  - AuthZ tiers: read vs run vs admin (install/remove), plus service-principal allowlists.
- Transactional install lifecycle:
  - Stage → write → atomic promote (`src/installer.py`) with rollback on failure.
  - No partial install directories become runnable.
- Concurrency safety:
  - Store-wide file lock with shared/exclusive modes (`src/locks.py`), applied in resolver operations (`src/resolver.py`).
- Operational endpoints:
  - `/healthz`, `/readyz`, `/version`, `/metrics` (`src/server.py`).
- Audit + metrics + egress hardening:
  - Structured audit events with redaction (`src/audit.py`, emitted from `src/server.py`).
  - Prometheus-style counters + latency summaries (`/metrics`).
  - Centralized outbound egress control + per-capability network allowlists (`src/egress.py`, enforced in `src/execution.py` and `src/resolver.py`).
- DX and ops artifacts:
  - YAML config format (`config.example.yaml`) + systemd unit (`systemd/unison-capability.service`) + Dockerfile (`Dockerfile`).
  - Canonical capability docs updated in `unison-docs/docs/platform/capabilities/*`.

## What remains
- Wire `unison-capability` into the planner/orchestrator runtime path (planner calling resolver before any execution) once the orchestrator planning loop is ready for it.
- Add sidecar templates (Envoy/OPA) specifically for `unison-capability` in `unison-security` when SPIFFE rollout includes it.
- Expand policy integration to call `unison-policy` for high-risk installs/runs (when the platform defines capability-level policy decisions).
- Replace interim file-based secrets backend with a `unison-storage` vault or `unison-security`-provided secrets client when available.

## Run locally
```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -c constraints.txt -r requirements.txt

# Safe default (loopback bind, auth required)
PYTHONPATH=src python src/server.py
```

## Run tests
```bash
. .venv/bin/activate
PYTEST_DISABLE_PLUGIN_AUTOLOAD=1 python -m pytest
```
