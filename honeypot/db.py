from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import Any

from flask import g

from .config import DECOY_PAYMENT_RECORDS

BASE_DIR = Path(__file__).resolve().parent.parent
DB_PATH = BASE_DIR / "honeypot.db"


def get_db() -> sqlite3.Connection:
    if "db" not in g:
        g.db = sqlite3.connect(DB_PATH)
        g.db.row_factory = sqlite3.Row
    return g.db


def close_db(_: Any = None) -> None:
    db = g.pop("db", None)
    if db is not None:
        db.close()


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
            geo_country TEXT NOT NULL DEFAULT 'Unknown',
            geo_region TEXT NOT NULL DEFAULT 'Unknown',
            geo_city TEXT NOT NULL DEFAULT 'Unknown',
            ip_scope TEXT NOT NULL DEFAULT 'unknown',
            suspicious_score INTEGER NOT NULL,
            suspicious_reasons TEXT NOT NULL,
            status_code INTEGER NOT NULL,
            persona TEXT NOT NULL,
            response_preview TEXT NOT NULL
        )
        """
    )
    event_log_columns = {row[1] for row in db.execute("PRAGMA table_info(event_logs)").fetchall()}
    expected_columns = {
        "geo_country": "TEXT NOT NULL DEFAULT 'Unknown'",
        "geo_region": "TEXT NOT NULL DEFAULT 'Unknown'",
        "geo_city": "TEXT NOT NULL DEFAULT 'Unknown'",
        "ip_scope": "TEXT NOT NULL DEFAULT 'unknown'",
    }
    for column_name, column_def in expected_columns.items():
        if column_name not in event_log_columns:
            db.execute(f"ALTER TABLE event_logs ADD COLUMN {column_name} {column_def}")
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
