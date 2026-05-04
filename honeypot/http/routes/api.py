from __future__ import annotations

import hashlib
import random
import secrets
import time
from collections import defaultdict, deque
from threading import Lock

from flask import Flask, Response, g, jsonify, request

from ...analysis import get_client_ip, normalize_text
from ...config import DECOY_USERS
from ...data import DB_PATH, export_payment_records_csv, lookup_cards, search_payments

LOGIN_RATE_WINDOW_SECONDS = 60.0
LOGIN_RATE_LIMIT = 5
LOGIN_LOCKOUT_SECONDS = 60

_login_attempts: dict[str, deque[float]] = defaultdict(lambda: deque(maxlen=64))
_login_lock = Lock()


def _login_rate_key() -> str:
    session_id = getattr(g, "session_id", None)
    if session_id:
        return f"sess:{session_id}"
    return f"ip:{get_client_ip()}"


def _record_login_attempt(key: str) -> int:
    now = time.monotonic()
    cutoff = now - LOGIN_RATE_WINDOW_SECONDS
    with _login_lock:
        attempts = _login_attempts[key]
        while attempts and attempts[0] < cutoff:
            attempts.popleft()
        attempts.append(now)
        return len(attempts)


def register_api_routes(app: Flask) -> None:
    @app.post("/login")
    def login() -> Response:
        time.sleep(random.uniform(0.15, 0.45))
        rate_key = _login_rate_key()
        attempt_count = _record_login_attempt(rate_key)
        if attempt_count > LOGIN_RATE_LIMIT:
            response = jsonify({
                "status": "rate_limited",
                "message": "account temporarily locked due to repeated failures",
                "retry_after": LOGIN_LOCKOUT_SECONDS,
            })
            response.status_code = 429
            response.headers["Retry-After"] = str(LOGIN_LOCKOUT_SECONDS)
            return response
        payload = request.get_json(silent=True) or {}
        username = request.form.get("username") or payload.get("username")
        password = request.form.get("password") or payload.get("password")
        if username in DECOY_USERS and password == DECOY_USERS[username]:
            token = hashlib.sha256(f"{username}:{password}".encode()).hexdigest()[:24]
            return jsonify({
                "status": "mfa_required",
                "verification_id": secrets.token_hex(12),
                "challenge": "totp",
                "hint": f"code sent to ****@{str(username).split('-')[0]}.internal",
            })
        if random.random() < 0.08 and username:
            return jsonify({
                "status": "mfa_required",
                "verification_id": secrets.token_hex(12),
                "challenge": "totp",
                "hint": "verification code required",
            })
        return jsonify({"status": "error", "message": "invalid credentials"}), 401

    @app.get("/api/payments/search")
    def payments_search() -> Response:
        results = search_payments(normalize_text(request.args.get("q", "")))
        return jsonify({"count": len(results), "results": results})

    @app.get("/api/cards/lookup")
    def card_lookup() -> Response:
        results = lookup_cards(request.args.get("last4", ""))
        return jsonify({"count": len(results), "results": results})

    @app.post("/api/transactions/refund")
    def refund() -> Response:
        payload = request.get_json(silent=True) or {}
        reference = payload.get("reference") or request.form.get("reference") or "unknown"
        amount = payload.get("amount") or request.form.get("amount") or "0"
        return jsonify({"status": "queued", "reference": reference, "refund_amount": amount, "processor": "settlement-core-2"})

    @app.get("/admin/export")
    def export_data() -> Response:
        return Response(export_payment_records_csv(), mimetype="text/csv")

    @app.get("/health")
    def health() -> Response:
        return jsonify({"status": "ok", "db_exists": DB_PATH.exists()})
