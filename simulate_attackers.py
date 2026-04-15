from __future__ import annotations

import random
import time
from typing import Any

import requests

BASE_URL = "http://127.0.0.1:5000"

ATTACKS: list[dict[str, Any]] = [
    {
        "method": "POST",
        "path": "/login",
        "headers": {"User-Agent": "sqlmap/1.8"},
        "data": {"username": "admin'--", "password": "anything"},
    },
    {
        "method": "GET",
        "path": "/api/payments/search",
        "headers": {"User-Agent": "curl/8.0"},
        "params": {"q": "' UNION SELECT * FROM cards --"},
    },
    {
        "method": "GET",
        "path": "/admin/export",
        "headers": {"User-Agent": "python-requests/2.32"},
    },
    {
        "method": "GET",
        "path": "/api/cards/lookup",
        "headers": {"User-Agent": "nikto/2.5.0"},
        "params": {"last4": "4242"},
    },
    {
        "method": "POST",
        "path": "/api/transactions/refund",
        "headers": {"User-Agent": "ReconBot/4.0", "Content-Type": "application/json"},
        "json": {"reference": "pay_1001", "amount": "9999", "note": "../../etc/passwd"},
    },
    {
        "method": "GET",
        "path": "/api/payments/search",
        "headers": {"User-Agent": "gobuster/3.6"},
        "params": {"q": "<script>alert(1)</script>"},
    },
]


def run_once(session: requests.Session, attack: dict[str, Any]) -> None:
    method = attack["method"]
    url = f"{BASE_URL}{attack['path']}"
    response = session.request(
        method=method,
        url=url,
        headers=attack.get("headers"),
        params=attack.get("params"),
        data=attack.get("data"),
        json=attack.get("json"),
        timeout=5,
    )
    print(f"{method} {attack['path']} -> {response.status_code}")


def main() -> None:
    session = requests.Session()
    for attack in ATTACKS:
        run_once(session, attack)
        time.sleep(random.uniform(0.2, 0.8))
    print(f"Simulation complete. Review {BASE_URL}/dashboard")


if __name__ == "__main__":
    main()
