## unison-capability (agent instructions)

Primary goals:
- Implement the Planner ↔ Capability Resolver contract in `docs/platform/capabilities/03-planner-capability-contract.md`.
- Enforce the Capability Manifest Specification v0.1 in `docs/platform/capabilities/02-capability-manifest-spec.md`.

Repository conventions:
- Python 3.12+.
- Prefer small, testable modules under `src/`.
- Validate all capability manifests against the bundled JSON Schema before persisting or executing.
- Do not add new manifest fields unless they are also documented in `unison-docs` (keep docs + schema in sync).

