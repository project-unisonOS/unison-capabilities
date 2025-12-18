from __future__ import annotations

import json
from pathlib import Path
from typing import Any, Dict

from jsonschema import Draft202012Validator

from errors import CapabilityManifestError


_SCHEMA_PATH = Path(__file__).resolve().parents[1] / "schemas" / "capability.manifest.v0.1.schema.json"


def load_manifest_validator() -> Draft202012Validator:
    try:
        raw = json.loads(_SCHEMA_PATH.read_text(encoding="utf-8"))
    except Exception as exc:  # pragma: no cover
        raise CapabilityManifestError(f"unable to read capability schema: {_SCHEMA_PATH}: {exc}") from exc
    return Draft202012Validator(raw)


_VALIDATOR = load_manifest_validator()


def validate_manifest(manifest: Dict[str, Any]) -> Dict[str, Any]:
    errors = sorted(_VALIDATOR.iter_errors(manifest), key=lambda e: list(e.path))
    if errors:
        msg = "; ".join(["/".join([str(p) for p in e.path]) + ": " + e.message for e in errors[:8]])
        raise CapabilityManifestError(f"manifest schema validation failed: {msg}")
    return manifest

