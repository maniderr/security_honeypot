from __future__ import annotations

import json
import random
import secrets
import time

from flask import Flask, Response, g, request

from .analysis import detect_persona, enrich_ip_context, evaluate_suspicion, get_client_ip, serialize_form, serialize_headers, utcnow
from .db import get_db

SKIP_LOG_PREFIXES: tuple[str, ...] = ("/dashboard", "/health")
SKIP_LOG_EXACT: frozenset[str] = frozenset({"/favicon.ico"})
SESSION_COOKIE_NAME = "hp_session"
LATENCY_MIN_SECONDS = 0.02
LATENCY_MAX_SECONDS = 0.18


def _should_skip(path: str) -> bool:
    if path in SKIP_LOG_EXACT:
        return True
    return any(path.startswith(prefix) for prefix in SKIP_LOG_PREFIXES)


def register_request_hooks(app: Flask) -> None:
    @app.before_request
    def trap_request() -> None:
        g.request_started_at = time.perf_counter()
        existing = request.cookies.get(SESSION_COOKIE_NAME)
        if existing:
            g.session_id = existing
            g.new_session = False
        else:
            g.session_id = secrets.token_hex(8)
            g.new_session = True
        if _should_skip(request.path):
            return
        time.sleep(random.uniform(LATENCY_MIN_SECONDS, LATENCY_MAX_SECONDS))

    @app.after_request
    def log_request(response: Response) -> Response:
        if getattr(g, "new_session", False):
            response.set_cookie(
                SESSION_COOKIE_NAME,
                g.session_id,
                max_age=60 * 60 * 24,
                httponly=True,
                samesite="Lax",
            )
        if _should_skip(request.path):
            return response
        headers = serialize_headers()
        body_text = request.get_data(cache=True, as_text=True)
        query_string = request.query_string.decode("utf-8", errors="ignore")
        score, reasons = evaluate_suspicion(request.path, query_string, body_text, headers)
        persona = detect_persona(request.path, score)
        preview = response.get_data(as_text=True)[:250]
        remote_addr = get_client_ip()
        geo_context = enrich_ip_context(remote_addr, headers)
        started_at = getattr(g, "request_started_at", None)
        latency_ms = int((time.perf_counter() - started_at) * 1000) if started_at else 0
        db = get_db()
        db.execute(
            """
            INSERT INTO event_logs (
                timestamp, remote_addr, method, path, query_string, headers_json, body_text,
                form_json, geo_country, geo_region, geo_city, ip_scope, suspicious_score,
                suspicious_reasons, status_code, persona, response_preview,
                session_id, latency_ms
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
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
                getattr(g, "session_id", "anon"),
                latency_ms,
            ),
        )
        db.commit()
        return response
