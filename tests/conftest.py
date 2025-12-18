from __future__ import annotations

import sys
from pathlib import Path


def pytest_configure() -> None:
    repo_root = Path(__file__).resolve().parents[1]
    src = repo_root / "src"
    if str(src) not in sys.path:
        sys.path.insert(0, str(src))

    # Allow importing `unison_common` from the workspace without requiring an installed wheel.
    workspace_root = repo_root.parent
    common_src = workspace_root / "unison-common" / "src"
    if common_src.exists() and str(common_src) not in sys.path:
        sys.path.insert(0, str(common_src))
