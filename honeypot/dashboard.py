from __future__ import annotations

import json

from flask import Flask, Response, jsonify, render_template

from .services import get_dashboard_snapshot


def register_dashboard_routes(app: Flask) -> None:
    @app.get("/dashboard/data")
    def dashboard_data() -> Response:
        return jsonify(get_dashboard_snapshot())

    @app.get("/dashboard")
    def dashboard() -> Response:
        data = get_dashboard_snapshot()
        chart_payload = json.dumps(
            {
                "persona": data["persona_counts"],
                "paths": data["top_paths"][:6],
                "risk": data["risk_buckets"],
                "ip_scope": data["ip_scope_counts"],
            }
        )
        return render_template("dashboard.html", data=data, chart_payload=chart_payload)
