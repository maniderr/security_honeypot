from __future__ import annotations

from flask import Flask, Response, render_template


def register_bait_routes(app: Flask) -> None:
    @app.get("/")
    def index() -> Response | str:
        return render_template(
            "landing.html",
            title="PayFlow Secure Gateway",
            subtitle="Merchant settlement and vault services",
        )

    @app.get("/auth/login")
    def auth_login_page() -> Response | str:
        return render_template(
            "auth_login.html",
            title="PayFlow Operator Login",
            subtitle="Privileged authentication",
        )

    @app.get("/portal/admin")
    def admin_portal() -> Response | str:
        return render_template(
            "admin_portal.html",
            title="PayFlow Admin Control Plane",
            subtitle="Restricted administrative access",
        )
