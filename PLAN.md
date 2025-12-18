# Seeded Capabilities Implementation Plan

This plan follows the planner contract and capability manifest spec in:
- `unison-docs/docs/platform/capabilities/overview.md`
- `unison-docs/docs/platform/capabilities/manifest-spec.md`
- `unison-docs/docs/platform/capabilities/planner-contract.md`

## File changes (high level)

### Manifest layering (base + local)
- Update `unison-capability/src/store.py`:
  - load `manifests/manifest.base.json` (read-only, shipped in image)
  - load `{store.base_dir}/manifest.local.json` (mutable)
  - merged view = base + local (local overrides by `id`)
  - writes go to local only
  - add `factory_reset()` (delete local manifest + local installs/payloads)
- Update `unison-capability/src/resolver.py`:
  - list/get/search/resolve use the merged manifest view
  - install writes to local manifest (and persists artifacts in local store)
- Add tests for merge precedence and reset behavior.

### Seeded baseline capabilities
- Add `unison-capability/manifests/manifest.base.json` with:
  - local tools (host info, bounded process inspection, scoped fs ops)
  - connectors (email/calendar, Slack/GitHub) disabled by default, OAuth required
  - skill packs (SKILL.md) for common workflows
- Add minimal implementations for seeded tools under `unison-capability/src/seed_tools.py` and skill pack runtime under `unison-capability/src/skillpack_runtime.py`.

### Registry adapters
- Refactor `unison-capability/src/discovery.py` to define adapter interface:
  - `list(query, filters) -> candidates[]`
  - `get(candidate_id) -> candidate`
  - `fetch(candidate_id) -> artifact/pointer` (minimal: returns manifest or manifest_url)
- Add adapters:
  - `StaticCatalogAdapter` (local JSON catalog shipped in repo)
  - `HttpCatalogAdapter` (HTTPS JSON index from configured URLs; deny-by-default egress)
- Update ranking so local manifests always win over registry candidates.
- Add tests: local preferred; registry suggested when missing.

### OAuth onboarding + secrets
- Add `unison-capability/src/secrets.py`:
  - `SecretsBackend` interface
  - `FileFernetSecretsBackend` (interim; encrypted file store; secrets referenced by `secret://...` handles)
- Add `unison-capability/src/oauth.py` implementing device authorization grant flows:
  - Google (Gmail/Calendar)
  - Microsoft (Graph)
- Add admin endpoints (guarded by existing authz tiers):
  - `POST /capability/oauth/start` (capability_id) → returns device code instructions + session_id
  - `POST /capability/oauth/complete` (session_id) → stores refresh token in secrets backend, updates local manifest to enable connector
- Add tests:
  - no secrets in logs
  - local manifest stores only secret refs
  - enabling flips `enabled` in local, not base

### Docs / ops
- Add `unison-docs/docs/platform/capabilities/seeded-capabilities.md`
- Update `unison-docs/docs/platform/capabilities/manifest-spec.md` to document:
  - base/local layering
  - new optional extensions: `enabled`, `requires_oauth`
  - registry adapters section (static + http catalogs; trust defaults)
- Update schemas:
  - `unison-docs/dev/specs/capability/manifest.v0.1.schema.json`
  - `unison-capability/schemas/capability.manifest.v0.1.schema.json`

## Demo (local)

1) Seeded local tool resolves immediately:
- `capability.resolve(step={intent: "host.info"})` returns a base capability without installation.

2) Missing intent suggests registry candidate (no auto-install):
- Configure `registries.http_catalogs` (allowlisted) or static catalog.
- `capability.search(intent="weather")` yields registry candidates with lower score than local.

3) OAuth onboarding enables a connector:
- `POST /capability/oauth/start` for a disabled connector (e.g., `connector.google.calendar`)
- Complete flow (stubbed demo provider) and call `POST /capability/oauth/complete`
- Confirm local manifest override sets `enabled: true` and `secrets` contains only `secret://...` refs.

