from __future__ import annotations

from flask import Flask

from .data import close_db, init_db
from .http import register_all_routes, register_request_hooks


def create_app() -> Flask:
    app = Flask(__name__)
    app.teardown_appcontext(close_db)
    register_request_hooks(app)
    register_all_routes(app)
    return app


__all__ = ["create_app", "init_db"]
