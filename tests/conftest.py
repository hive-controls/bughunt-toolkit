"""Make the repo root (for `bughunt`) and this dir (for cross-test imports) importable.

Tests live in tests/ but import both the `bughunt` package (repo root) and each
other as top-level modules (`from test_gate import ...`), so both directories must
be on sys.path regardless of how pytest is invoked.
"""
import os
import json
import site
import sys

import pytest

_here = os.path.dirname(os.path.abspath(__file__))
_root = os.path.dirname(_here)
for _p in (_root, _here):
    if _p not in sys.path:
        sys.path.insert(0, _p)


@pytest.fixture(scope="session")
def standalone_python():
    """Load dependency directories without executing editable-install .pth files."""
    dependencies = [*site.getsitepackages(), site.getusersitepackages()]
    bootstrap = (
        "import json, runpy, sys\n"
        "from pathlib import Path\n"
        "sys.path.extend(json.loads(sys.argv[1]))\n"
        "sys.argv = sys.argv[2:]\n"
        "sys.path.insert(0, str(Path(sys.argv[0]).resolve().parent))\n"
        "runpy.run_path(sys.argv[0], run_name='__main__')\n"
    )
    return [sys.executable, "-I", "-S", "-c", bootstrap, json.dumps(dependencies)]
