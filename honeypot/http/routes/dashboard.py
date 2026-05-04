from __future__ import annotations

import json
from datetime import datetime, timezone

from flask import Flask, Response, jsonify, render_template, request

from ...data import (
    EventFilters,
    export_events_csv,
    get_dashboard_snapshot,
    get_event_detail,
    list_filter_options,
)


def _normalize_time(raw: str | None) -> str | None:
    """Accept HTML datetime-local (YYYY-MM-DDTHH:MM) or full ISO and return an ISO UTC string."""
    if not raw:
        return None
    raw = raw.strip()
    if not raw:
        return None
    try:
        if len(raw) == 16:
            parsed = datetime.fromisoformat(raw).replace(tzinfo=timezone.utc)
        else:
            parsed = datetime.fromisoformat(raw)
            if parsed.tzinfo is None:
                parsed = parsed.replace(tzinfo=timezone.utc)
        return parsed.astimezone(timezone.utc).isoformat()
    except ValueError:
        return None


def _filters_from_query() -> EventFilters:
    try:
        min_score = int(request.args.get("min_score", "0") or 0)
    except ValueError:
        min_score = 0
    return EventFilters(
        persona=request.args.get("persona") or None,
        country=request.args.get("country") or None,
        ip_scope=request.args.get("ip_scope") or None,
        min_score=max(0, min_score),
        session_id=request.args.get("session_id") or None,
        start_time=_normalize_time(request.args.get("start_time")),
        end_time=_normalize_time(request.args.get("end_time")),
    )


def _chart_payload(data: dict[str, object]) -> str:
    return json.dumps(
        {
            "persona": data["persona_counts"],
            "paths": data["top_paths"][:6],
            "risk": data["risk_buckets"],
            "ip_scope": data["ip_scope_counts"],
            "timeseries": data["timeseries"],
        }
    )


def register_dashboard_routes(app: Flask) -> None:
    @app.get("/dashboard/data")
    def dashboard_data() -> Response:
        data = get_dashboard_snapshot(_filters_from_query())
        return jsonify({**data, "chart_payload": json.loads(_chart_payload(data))})

    @app.get("/dashboard/events/<int:event_id>")
    def dashboard_event_detail(event_id: int) -> Response:
        detail = get_event_detail(event_id)
        if detail is None:
            return jsonify({"error": "not_found"}), 404
        return jsonify(detail)

    @app.get("/dashboard/export")
    def dashboard_export() -> Response:
        filters = _filters_from_query()
        csv_text = export_events_csv(filters)
        timestamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
        filename = f"honeypot_events_{timestamp}.csv"
        return Response(
            csv_text,
            mimetype="text/csv",
            headers={"Content-Disposition": f'attachment; filename="{filename}"'},
        )

    @app.get("/dashboard")
    def dashboard() -> Response:
        filters = _filters_from_query()
        data = get_dashboard_snapshot(filters)
        options = list_filter_options()
        return render_template(
            "dashboard.html",
            data=data,
            chart_payload=_chart_payload(data),
            options=options,
        )
