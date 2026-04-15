from __future__ import annotations

import argparse
import csv
import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "honeypot.db"
DEFAULT_OUTPUT = BASE_DIR / "captured_events.csv"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--output", default=str(DEFAULT_OUTPUT), help="Path to CSV output file")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    output_path = Path(args.output).resolve()
    if not DB_PATH.exists():
        raise SystemExit("honeypot.db does not exist. Start the honeypot first.")
    db = sqlite3.connect(DB_PATH)
    db.row_factory = sqlite3.Row
    rows = db.execute(
        """
        SELECT id, timestamp, remote_addr, method, path, query_string, form_json,
               geo_country, geo_region, geo_city, ip_scope, suspicious_score,
               suspicious_reasons, status_code, persona, response_preview
        FROM event_logs
        ORDER BY id ASC
        """
    ).fetchall()
    db.close()
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("w", newline="", encoding="utf-8") as csv_file:
        fieldnames = [
            "id",
            "timestamp",
            "remote_addr",
            "method",
            "path",
            "query_string",
            "form_json",
            "geo_country",
            "geo_region",
            "geo_city",
            "ip_scope",
            "suspicious_score",
            "suspicious_reasons",
            "status_code",
            "persona",
            "response_preview",
        ]
        writer = csv.DictWriter(csv_file, fieldnames=fieldnames)
        writer.writeheader()
        for row in rows:
            writer.writerow(dict(row))
    print(f"Exported {len(rows)} captured events to {output_path}")


if __name__ == "__main__":
    main()
