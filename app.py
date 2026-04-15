from __future__ import annotations

import hashlib
import html
import json
import os
import sqlite3
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

from flask import Flask, Response, g, jsonify, make_response, request

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "honeypot.db"

app = Flask(__name__)

DECOY_USERS = {
    "svc-payments": "P@yments2024!",
    "db_admin": "CardVault#2024",
    "reporting": "Analytics!2024",
}

DECOY_PAYMENT_RECORDS = [
    {
        "record_id": "pay_1001",
        "cardholder": "Elena M.",
        "last4": "4242",
        "brand": "Visa",
        "amount": 219.94,
        "currency": "USD",
        "status": "settled",
        "email": "elena.merchant@example-payments.com",
    },
    {
        "record_id": "pay_1002",
        "cardholder": "Marco T.",
        "last4": "1881",
        "brand": "Mastercard",
        "amount": 58.11,
        "currency": "EUR",
        "status": "refunded",
        "email": "marco.billing@example-payments.com",
    },
    {
        "record_id": "pay_1003",
        "cardholder": "Priya K.",
        "last4": "0005",
        "brand": "Amex",
        "amount": 910.35,
        "currency": "USD",
        "status": "flagged",
        "email": "priya.ops@example-payments.com",
    },
]

SUSPICIOUS_MARKERS = [
    "union select",
    " or 1=1",
    "../",
    "<script",
    "drop table",
    "xp_cmdshell",
    "information_schema",
    "admin'--",
    "../../",
]


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


@app.teardown_appcontext
def close_db(_: Any) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


def utcnow() -> str:
    return datetime.now(timezone.utc).isoformat()


def init_db() -> None:
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS payment_records (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            record_id TEXT UNIQUE NOT NULL,
            cardholder TEXT NOT NULL,
            last4 TEXT NOT NULL,
            brand TEXT NOT NULL,
            amount REAL NOT NULL,
            currency TEXT NOT NULL,
            status TEXT NOT NULL,
            email TEXT NOT NULL
        )
        """
    )
    db.execute(
        """
        CREATE TABLE IF NOT EXISTS event_logs (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            timestamp TEXT NOT NULL,
            remote_addr TEXT,
            method TEXT NOT NULL,
            path TEXT NOT NULL,
            query_string TEXT,
            headers_json TEXT NOT NULL,
            body_text TEXT,
            form_json TEXT NOT NULL,
            suspicious_score INTEGER NOT NULL,
            suspicious_reasons TEXT NOT NULL,
            status_code INTEGER NOT NULL,
            persona TEXT NOT NULL,
            response_preview TEXT NOT NULL
        )
        """
    )
    existing = db.execute("SELECT COUNT(*) AS count FROM payment_records").fetchone()["count"]
    if existing == 0:
        db.executemany(
            """
            INSERT INTO payment_records (
                record_id, cardholder, last4, brand, amount, currency, status, email
            ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)
            """,
            [
                (
                    row["record_id"],
                    row["cardholder"],
                    row["last4"],
                    row["brand"],
                    row["amount"],
                    row["currency"],
                    row["status"],
                    row["email"],
                )
                for row in DECOY_PAYMENT_RECORDS
            ],
        )
    db.commit()
    db.close()


def normalize_text(payload: str) -> str:
    return payload.lower().strip()


def evaluate_suspicion(path: str, query_string: str, body_text: str, headers: dict[str, str]) -> tuple[int, list[str]]:
    score = 0
    reasons: list[str] = []
    combined = "\n".join([path, query_string, body_text, json.dumps(headers)]).lower()
    for marker in SUSPICIOUS_MARKERS:
        if marker in combined:
            score += 3
            reasons.append(f"marker:{marker}")
    user_agent = headers.get("User-Agent", "")
    suspicious_agents = ["sqlmap", "nikto", "curl", "python-requests", "gobuster"]
    for agent in suspicious_agents:
        if agent in user_agent.lower():
            score += 2
            reasons.append(f"agent:{agent}")
    high_value_paths = ["/admin", "/dump", "/export", "/cards", "/vault", "/config"]
    if any(segment in path.lower() for segment in high_value_paths):
        score += 2
        reasons.append("high_value_path")
    if len(body_text) > 500:
        score += 1
        reasons.append("large_body")
    return score, reasons


def detect_persona(path: str, score: int) -> str:
    lowered = path.lower()
    if score >= 6:
        return "active_intruder"
    if any(term in lowered for term in ["admin", "export", "cards", "refund"]):
        return "credential_stuffer"
    return "curious_recon"


def serialize_headers() -> dict[str, str]:
    return {key: value for key, value in request.headers.items()}


def serialize_form() -> dict[str, Any]:
    if request.form:
        return {key: request.form.getlist(key) if len(request.form.getlist(key)) > 1 else request.form.get(key) for key in request.form.keys()}
    if request.query_string:
        parsed = parse_qs(request.query_string.decode("utf-8", errors="ignore"))
        return {key: values if len(values) > 1 else values[0] for key, values in parsed.items()}
    return {}


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
    db = get_db()
    db.execute(
        """
        INSERT INTO event_logs (
            timestamp, remote_addr, method, path, query_string, headers_json, body_text,
            form_json, suspicious_score, suspicious_reasons, status_code, persona, response_preview
        ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)
        """,
        (
            utcnow(),
            request.headers.get("X-Forwarded-For", request.remote_addr),
            request.method,
            request.path,
            query_string,
            json.dumps(headers),
            body_text,
            json.dumps(serialize_form()),
            score,
            json.dumps(reasons),
            response.status_code,
            persona,
            preview,
        ),
    )
    db.commit()
    return response


@app.get("/")
def index() -> Response:
    return make_response(
        """
        <html>
            <head><title>PayFlow Secure Gateway</title></head>
            <body style=\"font-family: Arial; margin: 40px;\">
                <h1>PayFlow Secure Gateway</h1>
                <p>Merchant settlement, refund, and vault synchronization services.</p>
                <ul>
                    <li>POST /login</li>
                    <li>GET /api/payments/search?q=</li>
                    <li>GET /api/cards/lookup?last4=</li>
                    <li>POST /api/transactions/refund</li>
                    <li>GET /admin/export</li>
                    <li>GET /dashboard</li>
                </ul>
            </body>
        </html>
        """
    )


@app.post("/login")
def login() -> Response:
    payload = request.get_json(silent=True) or {}
    username = request.form.get("username") or payload.get("username")
    password = request.form.get("password") or payload.get("password")
    if username in DECOY_USERS and password == DECOY_USERS[username]:
        token = hashlib.sha256(f"{username}:{password}".encode()).hexdigest()[:24]
        return jsonify({"status": "ok", "token": token, "role": "ops"})
    return jsonify({"status": "error", "message": "invalid credentials"}), 401


@app.get("/api/payments/search")
def payments_search() -> Response:
    q = normalize_text(request.args.get("q", ""))
    db = get_db()
    rows = db.execute(
        """
        SELECT record_id, cardholder, last4, brand, amount, currency, status, email
        FROM payment_records
        WHERE lower(record_id) LIKE ?
           OR lower(cardholder) LIKE ?
           OR lower(email) LIKE ?
           OR lower(status) LIKE ?
        ORDER BY id ASC
        LIMIT 25
        """,
        (f"%{q}%", f"%{q}%", f"%{q}%", f"%{q}%"),
    ).fetchall()
    return jsonify({"count": len(rows), "results": [dict(row) for row in rows]})


@app.get("/api/cards/lookup")
def card_lookup() -> Response:
    last4 = request.args.get("last4", "")
    db = get_db()
    rows = db.execute(
        """
        SELECT record_id, cardholder, last4, brand, amount, currency, status
        FROM payment_records
        WHERE last4 = ?
        """,
        (last4,),
    ).fetchall()
    return jsonify({"count": len(rows), "results": [dict(row) for row in rows]})


@app.post("/api/transactions/refund")
def refund() -> Response:
    payload = request.get_json(silent=True) or {}
    reference = payload.get("reference") or request.form.get("reference") or "unknown"
    amount = payload.get("amount") or request.form.get("amount") or "0"
    return jsonify({"status": "queued", "reference": reference, "refund_amount": amount, "processor": "settlement-core-2"})


@app.get("/admin/export")
def export_data() -> Response:
    db = get_db()
    rows = db.execute(
        """
        SELECT record_id, cardholder, last4, brand, amount, currency, status, email
        FROM payment_records
        ORDER BY id ASC
        """
    ).fetchall()
    csv_lines = ["record_id,cardholder,last4,brand,amount,currency,status,email"]
    for row in rows:
        csv_lines.append(
            ",".join(
                [
                    str(row["record_id"]),
                    str(row["cardholder"]),
                    str(row["last4"]),
                    str(row["brand"]),
                    str(row["amount"]),
                    str(row["currency"]),
                    str(row["status"]),
                    str(row["email"]),
                ]
            )
        )
    return Response("\n".join(csv_lines), mimetype="text/csv")


@app.get("/health")
def health() -> Response:
    return jsonify({"status": "ok", "db_exists": os.path.exists(DB_PATH)})


@app.get("/dashboard/data")
def dashboard_data() -> Response:
    db = get_db()
    rows = db.execute(
        """
        SELECT timestamp, remote_addr, method, path, suspicious_score, suspicious_reasons, persona, status_code, body_text
        FROM event_logs
        ORDER BY id DESC
        LIMIT 100
        """
    ).fetchall()
    all_rows = [dict(row) for row in rows]
    persona_counts = Counter(row["persona"] for row in all_rows)
    path_counts = Counter(row["path"] for row in all_rows)
    top_scores = sorted(all_rows, key=lambda row: row["suspicious_score"], reverse=True)[:10]
    return jsonify(
        {
            "event_count": len(all_rows),
            "high_risk_events": sum(1 for row in all_rows if row["suspicious_score"] >= 5),
            "persona_counts": dict(persona_counts),
            "top_paths": path_counts.most_common(10),
            "recent_events": all_rows[:20],
            "top_scored_events": top_scores,
        }
    )


@app.get("/dashboard")
def dashboard() -> Response:
    data = dashboard_data().get_json()
    event_rows = []
    for row in data["recent_events"]:
        reasons = html.escape(row["suspicious_reasons"])
        event_rows.append(
            "<tr>"
            f"<td>{html.escape(row['timestamp'])}</td>"
            f"<td>{html.escape(str(row['remote_addr']))}</td>"
            f"<td>{html.escape(row['method'])}</td>"
            f"<td>{html.escape(row['path'])}</td>"
            f"<td>{row['suspicious_score']}</td>"
            f"<td>{html.escape(row['persona'])}</td>"
            f"<td>{reasons}</td>"
            "</tr>"
        )
    top_paths = "".join(
        f"<li>{html.escape(path)}: {count}</li>" for path, count in data["top_paths"]
    )
    persona_counts = "".join(
        f"<li>{html.escape(persona)}: {count}</li>" for persona, count in data["persona_counts"].items()
    )
    html_page = f"""
    <html>
        <head>
            <title>PayFlow Honeypot Dashboard</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 30px; background: #0f172a; color: #e2e8f0; }}
                .card {{ background: #111827; border-radius: 8px; padding: 20px; margin-bottom: 20px; }}
                table {{ width: 100%; border-collapse: collapse; }}
                th, td {{ border-bottom: 1px solid #334155; padding: 10px; text-align: left; font-size: 14px; }}
                h1, h2 {{ margin-top: 0; }}
                .metrics {{ display: flex; gap: 20px; }}
                .metric {{ flex: 1; background: #1e293b; padding: 16px; border-radius: 8px; }}
            </style>
        </head>
        <body>
            <h1>PayFlow Honeypot Dashboard</h1>
            <div class="metrics">
                <div class="metric"><strong>Captured events</strong><br>{data['event_count']}</div>
                <div class="metric"><strong>High risk events</strong><br>{data['high_risk_events']}</div>
            </div>
            <div class="card">
                <h2>Persona counts</h2>
                <ul>{persona_counts}</ul>
            </div>
            <div class="card">
                <h2>Top targeted paths</h2>
                <ul>{top_paths}</ul>
            </div>
            <div class="card">
                <h2>Recent events</h2>
                <table>
                    <thead>
                        <tr>
                            <th>Timestamp</th>
                            <th>Remote IP</th>
                            <th>Method</th>
                            <th>Path</th>
                            <th>Score</th>
                            <th>Persona</th>
                            <th>Reasons</th>
                        </tr>
                    </thead>
                    <tbody>
                        {''.join(event_rows)}
                    </tbody>
                </table>
            </div>
        </body>
    </html>
    """
    return make_response(html_page)


if __name__ == "__main__":
    init_db()
    app.run(host="0.0.0.0", port=5000, debug=False)
