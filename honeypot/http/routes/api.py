from __future__ import annotations

import hashlib
import random
import secrets
import time

from flask import Flask, Response, jsonify, request

from ...analysis import normalize_text
from ...config import DECOY_USERS
from ...data import DB_PATH, export_payment_records_csv, lookup_cards, search_payments


def register_api_routes(app: Flask) -> None:
    @app.post("/login")
    def login() -> Response:
        time.sleep(random.uniform(0.15, 0.45))
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
