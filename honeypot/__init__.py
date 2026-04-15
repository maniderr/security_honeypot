from __future__ import annotations

from flask import Flask

from .api_routes import register_api_routes
from .bait_routes import register_bait_routes
from .dashboard import register_dashboard_routes
from .db import close_db, init_db
from .hooks import register_request_hooks


def create_app() -> Flask:
    app = Flask(__name__)
    app.teardown_appcontext(close_db)
    register_request_hooks(app)
    register_bait_routes(app)
    register_api_routes(app)
    register_dashboard_routes(app)
    return app


__all__ = ["create_app", "init_db"]
