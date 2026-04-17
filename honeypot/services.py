from __future__ import annotations

import csv
import io
from collections import Counter
from dataclasses import dataclass
from datetime import datetime, timedelta, timezone

from .db import get_db


@dataclass(frozen=True)
class EventFilters:
    persona: str | None = None
    country: str | None = None
    ip_scope: str | None = None
    min_score: int = 0
    session_id: str | None = None
    limit: int = 250


def _build_where(filters: EventFilters) -> tuple[str, list[object]]:
    clauses: list[str] = []
    params: list[object] = []
    if filters.persona:
        clauses.append("persona = ?")
        params.append(filters.persona)
    if filters.country:
        clauses.append("geo_country = ?")
        params.append(filters.country)
    if filters.ip_scope:
        clauses.append("ip_scope = ?")
        params.append(filters.ip_scope)
    if filters.min_score > 0:
        clauses.append("suspicious_score >= ?")
        params.append(filters.min_score)
    if filters.session_id:
        clauses.append("session_id = ?")
        params.append(filters.session_id)
    where_clause = (" WHERE " + " AND ".join(clauses)) if clauses else ""
    return where_clause, params


def search_payments(query: str) -> list[dict[str, object]]:
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
        (f"%{query}%", f"%{query}%", f"%{query}%", f"%{query}%"),
    ).fetchall()
    return [dict(row) for row in rows]


def lookup_cards(last4: str) -> list[dict[str, object]]:
    db = get_db()
    rows = db.execute(
        """
        SELECT record_id, cardholder, last4, brand, amount, currency, status
        FROM payment_records
        WHERE last4 = ?
        """,
        (last4,),
    ).fetchall()
    return [dict(row) for row in rows]


def export_payment_records_csv() -> str:
    db = get_db()
    rows = db.execute(
        """
        SELECT record_id, cardholder, last4, brand, amount, currency, status, email
        FROM payment_records
        ORDER BY id ASC
        """
    ).fetchall()
    buffer = io.StringIO()
    writer = csv.writer(buffer)
    writer.writerow(["record_id", "cardholder", "last4", "brand", "amount", "currency", "status", "email"])
    for row in rows:
        writer.writerow([
            row["record_id"],
            row["cardholder"],
            row["last4"],
            row["brand"],
            row["amount"],
            row["currency"],
            row["status"],
            row["email"],
        ])
    return buffer.getvalue()


def _compute_timeseries(rows: list[dict[str, object]], minutes: int = 60) -> list[list[object]]:
    now = datetime.now(timezone.utc).replace(second=0, microsecond=0)
    buckets: dict[str, int] = {}
    for offset in range(minutes - 1, -1, -1):
        bucket = (now - timedelta(minutes=offset)).strftime("%H:%M")
        buckets[bucket] = 0
    cutoff = now - timedelta(minutes=minutes - 1)
    for row in rows:
        raw = row.get("timestamp")
        if not isinstance(raw, str):
            continue
        try:
            ts = datetime.fromisoformat(raw)
        except ValueError:
            continue
        if ts.tzinfo is None:
            ts = ts.replace(tzinfo=timezone.utc)
        ts = ts.astimezone(timezone.utc).replace(second=0, microsecond=0)
        if ts < cutoff:
            continue
        key = ts.strftime("%H:%M")
        if key in buckets:
            buckets[key] += 1
    return [[label, count] for label, count in buckets.items()]


def get_dashboard_snapshot(filters: EventFilters | None = None) -> dict[str, object]:
    filters = filters or EventFilters()
    db = get_db()
    where_clause, params = _build_where(filters)
    rows = db.execute(
        f"""
        SELECT id, timestamp, remote_addr, method, path, suspicious_score, suspicious_reasons,
               persona, status_code, geo_country, geo_region, geo_city, ip_scope,
               session_id, latency_ms
        FROM event_logs
        {where_clause}
        ORDER BY id DESC
        LIMIT ?
        """,
        [*params, filters.limit],
    ).fetchall()
    all_rows = [dict(row) for row in rows]
    persona_counts = Counter(row["persona"] for row in all_rows)
    path_counts = Counter(row["path"] for row in all_rows)
    country_counts = Counter(row["geo_country"] for row in all_rows)
    ip_scope_counts = Counter(row["ip_scope"] for row in all_rows)
    session_counts = Counter(row["session_id"] for row in all_rows)
    risk_buckets = {
        "low": sum(1 for row in all_rows if row["suspicious_score"] <= 2),
        "medium": sum(1 for row in all_rows if 3 <= row["suspicious_score"] <= 5),
        "high": sum(1 for row in all_rows if row["suspicious_score"] >= 6),
    }
    top_scores = sorted(all_rows, key=lambda row: row["suspicious_score"], reverse=True)[:10]
    avg_latency = int(sum(row.get("latency_ms", 0) or 0 for row in all_rows) / len(all_rows)) if all_rows else 0
    return {
        "event_count": len(all_rows),
        "high_risk_events": sum(1 for row in all_rows if row["suspicious_score"] >= 5),
        "persona_counts": dict(persona_counts),
        "top_paths": path_counts.most_common(10),
        "country_counts": dict(country_counts),
        "ip_scope_counts": dict(ip_scope_counts),
        "risk_buckets": risk_buckets,
        "recent_events": all_rows[:20],
        "top_scored_events": top_scores,
        "timeseries": _compute_timeseries(all_rows),
        "unique_sessions": len(session_counts),
        "top_sessions": session_counts.most_common(8),
        "avg_latency_ms": avg_latency,
        "filters": {
            "persona": filters.persona or "",
            "country": filters.country or "",
            "ip_scope": filters.ip_scope or "",
            "min_score": filters.min_score,
            "session_id": filters.session_id or "",
        },
    }


def get_event_detail(event_id: int) -> dict[str, object] | None:
    db = get_db()
    row = db.execute(
        """
        SELECT id, timestamp, remote_addr, method, path, query_string, headers_json,
               body_text, form_json, geo_country, geo_region, geo_city, ip_scope,
               suspicious_score, suspicious_reasons, status_code, persona,
               response_preview, session_id, latency_ms
        FROM event_logs
        WHERE id = ?
        """,
        (event_id,),
    ).fetchone()
    return dict(row) if row is not None else None


def list_filter_options() -> dict[str, list[str]]:
    db = get_db()
    personas = [row[0] for row in db.execute("SELECT DISTINCT persona FROM event_logs ORDER BY persona").fetchall()]
    countries = [row[0] for row in db.execute("SELECT DISTINCT geo_country FROM event_logs ORDER BY geo_country").fetchall()]
    scopes = [row[0] for row in db.execute("SELECT DISTINCT ip_scope FROM event_logs ORDER BY ip_scope").fetchall()]
    return {"personas": personas, "countries": countries, "ip_scopes": scopes}
