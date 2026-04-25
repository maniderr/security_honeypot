from __future__ import annotations

from flask import Flask

from .api import register_api_routes
from .bait import register_bait_routes
from .dashboard import register_dashboard_routes
from .scanner_decoys import register_scanner_decoys


def register_all_routes(app: Flask) -> None:
    register_bait_routes(app)
    register_api_routes(app)
    register_scanner_decoys(app)
    register_dashboard_routes(app)


__all__ = [
    "register_all_routes",
    "register_api_routes",
    "register_bait_routes",
    "register_dashboard_routes",
    "register_scanner_decoys",
]
