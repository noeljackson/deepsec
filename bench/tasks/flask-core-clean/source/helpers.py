from __future__ import annotations

import os


def get_debug_flag() -> bool:
    """Return whether Flask's debug mode is on.

    Reads ``FLASK_DEBUG`` from the environment. This is library code:
    the user opts in by setting the env var. Not an injection sink."""
    val = os.environ.get("FLASK_DEBUG")
    if not val:
        return False
    return val.lower() not in {"0", "false", "no"}


def get_load_dotenv(default: bool = True) -> bool:
    val = os.environ.get("FLASK_SKIP_DOTENV")
    if val is None:
        return default
    return val.lower() in {"0", "false", "no"}


def get_root_path(import_name: str) -> str:
    import sys

    mod = sys.modules.get(import_name)
    if mod is not None and hasattr(mod, "__file__"):
        return os.path.dirname(os.path.abspath(mod.__file__))
    return os.getcwd()
