from __future__ import annotations

import argparse
import sqlite3
from pathlib import Path

BASE_DIR = Path(__file__).resolve().parent
DB_PATH = BASE_DIR / "honeypot.db"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--force", action="store_true", help="Skip confirmation prompt")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if not DB_PATH.exists():
        print("honeypot.db does not exist. Nothing to clear.")
        return
    if not args.force:
        confirmation = input("Delete all captured event logs from honeypot.db? Type yes to continue: ").strip().lower()
        if confirmation != "yes":
            print("Reset cancelled.")
            return
    db = sqlite3.connect(DB_PATH)
    cursor = db.cursor()
    cursor.execute("DELETE FROM event_logs")
    cursor.execute("DELETE FROM sqlite_sequence WHERE name = 'event_logs'")
    db.commit()
    deleted_rows = cursor.rowcount
    db.close()
    print(f"Cleared captured honeypot events from {DB_PATH}.")
    print(f"Last statement affected {deleted_rows} SQLite rows.")


if __name__ == "__main__":
    main()
