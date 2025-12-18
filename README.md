# unison-capability

Core Capability Resolver service for UnisonOS.

This service implements the Resolver API defined in `docs/platform/capabilities/03-planner-capability-contract.md`:
- `capability.search(intent, constraints)`
- `capability.resolve(step)`
- `capability.install(candidate)`
- `capability.run(capability_id, args)`
- `capability.list()`, `capability.get()`, `capability.remove()`

## What it does

- Capability discovery (installed store + optional MCP registry discovery)
- Resolution (choose best candidate under policy + constraints)
- Installation (validate + persist manifest; optional remote manifest fetch with digest pinning)
- Execution (local command tools; MCP tool calls)
- Manifest persistence (filesystem store)

Canonical spec + schema live in `unison-docs/docs/platform/capabilities/` and `unison-docs/dev/specs/capability/manifest.v0.1.schema.json`.

## Seeded capabilities

Images ship a read-only baseline catalog at `manifests/manifest.base.json`. Runtime changes are written to the local catalog at `${UNISON_CAPABILITY_STORE_DIR}/manifest.local.json`. The resolver view is the merged catalog (local overrides base by `id`).

## Environment variables

- `UNISON_CAPABILITY_STORE_DIR` (default: `/var/lib/unison/capabilities`)
- `UNISON_MCP_REGISTRY_URL` (optional; same discovery shape used by `unison-orchestrator` companion)
- `UNISON_CAPABILITY_TRUST_ALLOW` (default: `local,verified`)
- `UNISON_CAPABILITY_ALLOW_COMMUNITY` (default: `false`)
- `UNISON_CAPABILITY_ALLOW_UNTRUSTED` (default: `false`)
- `UNISON_CAPABILITY_CONFIG` (optional; YAML config path; default `/etc/unison/unison-capability.yaml` if present)
- `UNISON_CAPABILITY_AUTH_MODE` (`unison_jwt|static_bearer|disabled`)
- `UNISON_CAPABILITY_BEARER_TOKEN` (static bearer token when `static_bearer`)
- `UNISON_CAPABILITY_UNSAFE_NO_AUTH` (dev-only; required when `AUTH_MODE=disabled`)
- `UNISON_CAPABILITY_UNSAFE_ALLOW_NONLOCAL` (dev-only; allow non-loopback clients)
- `UNISON_CAPABILITY_SECRETS_KEY` (required for OAuth onboarding; Fernet key)
- `UNISON_OAUTH_GOOGLE_CLIENT_ID`, `UNISON_OAUTH_GOOGLE_CLIENT_SECRET` (OAuth client credentials)
- `UNISON_OAUTH_MICROSOFT_CLIENT_ID`, `UNISON_OAUTH_MICROSOFT_CLIENT_SECRET` (OAuth client credentials)

## Security defaults
- Listens on loopback only by default and denies non-local clients at runtime (even if bound to `0.0.0.0`).
- Requires auth for all capability endpoints (search/resolve/install/run/list/get/remove); only `/healthz`, `/readyz`, `/version`, `/metrics` are unauthenticated.
- Installs are transactional (staged + atomic promotion) and protected by a filesystem lock.

## Config file
See `config.example.yaml`.

## Run locally

```bash
python3 -m venv .venv
. .venv/bin/activate
pip install -c constraints.txt -r requirements.txt
PYTHONPATH=src uvicorn server:app --host 0.0.0.0 --port 8102
```

Prefer the safe entrypoint (loopback by default):
```bash
PYTHONPATH=src python src/server.py
```

## Demo

`scripts/demo.py` exercises:
- Intent → local tool (built-in `demo.echo`)
- Intent → external MCP discovery → install → execute → persist (against a stub registry in the script)

```bash
PYTHONPATH=src python scripts/demo.py
```
