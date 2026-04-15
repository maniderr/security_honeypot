from __future__ import annotations

from collections import Counter

from .db import get_db


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
    return "\n".join(csv_lines)


def get_dashboard_snapshot() -> dict[str, object]:
    db = get_db()
    rows = db.execute(
        """
        SELECT timestamp, remote_addr, method, path, suspicious_score, suspicious_reasons,
               persona, status_code, body_text, geo_country, geo_region, geo_city, ip_scope
        FROM event_logs
        ORDER BY id DESC
        LIMIT 250
        """
    ).fetchall()
    all_rows = [dict(row) for row in rows]
    persona_counts = Counter(row["persona"] for row in all_rows)
    path_counts = Counter(row["path"] for row in all_rows)
    country_counts = Counter(row["geo_country"] for row in all_rows)
    ip_scope_counts = Counter(row["ip_scope"] for row in all_rows)
    risk_buckets = {
        "low": sum(1 for row in all_rows if row["suspicious_score"] <= 2),
        "medium": sum(1 for row in all_rows if 3 <= row["suspicious_score"] <= 5),
        "high": sum(1 for row in all_rows if row["suspicious_score"] >= 6),
    }
    top_scores = sorted(all_rows, key=lambda row: row["suspicious_score"], reverse=True)[:10]
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
    }
