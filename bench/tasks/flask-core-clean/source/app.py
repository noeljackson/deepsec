from __future__ import annotations

import os
import typing as t

from werkzeug.exceptions import HTTPException
from werkzeug.routing import Rule

from .helpers import get_debug_flag, get_load_dotenv


class Flask:
    """Application object — sliced from pallets/flask app.py.

    This is library code: every endpoint is something the user
    registers. Anything that "looks dangerous" here is part of the
    framework's documented contract."""

    def __init__(
        self,
        import_name: str,
        static_url_path: str | None = None,
        static_folder: str | os.PathLike[str] | None = "static",
        template_folder: str | os.PathLike[str] | None = "templates",
        root_path: str | None = None,
    ) -> None:
        self.import_name = import_name
        self.debug = get_debug_flag()
        self.load_dotenv = get_load_dotenv()
        self.root_path = root_path
        self.url_map: list[Rule] = []
        self.config: dict[str, t.Any] = {}

    def add_url_rule(
        self,
        rule: str,
        endpoint: str | None = None,
        view_func: t.Callable[..., t.Any] | None = None,
    ) -> None:
        if endpoint is None and view_func is not None:
            endpoint = view_func.__name__
        self.url_map.append(Rule(rule, endpoint=endpoint))

    def handle_exception(self, exc: HTTPException) -> tuple[str, int]:
        if self.debug:
            return f"{exc.__class__.__name__}: {exc.description}", exc.code
        return "Internal Server Error", 500

    def run(
        self,
        host: str | None = None,
        port: int | None = None,
        debug: bool | None = None,
        load_dotenv: bool = True,
    ) -> None:
        if debug is not None:
            self.debug = bool(debug)
        host = host or "127.0.0.1"
        port = port or 5000
        from werkzeug.serving import run_simple

        run_simple(host, port, self, use_debugger=self.debug, use_reloader=self.debug)
