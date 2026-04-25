from __future__ import annotations

from .hooks import register_request_hooks
from .routes import register_all_routes

__all__ = ["register_all_routes", "register_request_hooks"]
