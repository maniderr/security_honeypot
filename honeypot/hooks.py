from __future__ import annotations

import json

from flask import Flask, Response, request

from .analysis import detect_persona, enrich_ip_context, evaluate_suspicion, get_client_ip, serialize_form, serialize_headers, utcnow
from .db import get_db


def register_request_hooks(app: Flask) -> None:
    @app.before_request
    def trap_request() -> None:
        if request.path.startswith("/dashboard") or request.path.startswith("/health"):
            return
        if request.path == "/favicon.ico":
            return

    @app.after_request
    def log_request(response: Response) -> Response:
        if request.path.startswith("/dashboard") or request.path.startswith("/health") or request.path == "/favicon.ico":
            return response
        headers = serialize_headers()
        body_text = request.get_data(cache=True, as_text=True)
        query_string = request.query_string.decode("utf-8", errors="ignore")
        score, reasons = evaluate_suspicion(request.path, query_string, body_text, headers)
        persona = detect_persona(request.path, score)
        preview = response.get_data(as_text=True)[:250]
        remote_addr = get_client_ip()
        geo_context = enrich_ip_context(remote_addr, headers)
        db = get_db()
        db.execute(
            """
            INSERT INTO event_logs (
                timestamp, remote_addr, method, path, query_string, headers_json, body_text,
                form_json, geo_country, geo_region, geo_city, ip_scope, suspicious_score,
                suspicious_reasons, status_code, persona, response_preview
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
            """,
            (
                utcnow(),
                remote_addr,
                request.method,
                request.path,
                query_string,
                json.dumps(headers),
                body_text,
                json.dumps(serialize_form()),
                geo_context["geo_country"],
                geo_context["geo_region"],
                geo_context["geo_city"],
                geo_context["ip_scope"],
                score,
                json.dumps(reasons),
                response.status_code,
                persona,
                preview,
            ),
        )
        db.commit()
        return response
