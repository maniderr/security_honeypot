from __future__ import annotations

import argparse
import random
import time
from typing import Any

import requests

DEFAULT_BASE_URL = "http://127.0.0.1:5000"

ATTACKER_PROFILES = [
    {
        "X-Forwarded-For": "185.220.101.45",
        "X-Country-Code": "DE",
        "X-Region": "Hesse",
        "X-City": "Frankfurt",
    },
    {
        "X-Forwarded-For": "31.7.62.18",
        "X-Country-Code": "NL",
        "X-Region": "North Holland",
        "X-City": "Amsterdam",
    },
    {
        "X-Forwarded-For": "102.143.81.9",
        "X-Country-Code": "RO",
        "X-Region": "Bucharest",
        "X-City": "Bucharest",
    },
]

ATTACKS: list[dict[str, Any]] = [
    {
        "method": "GET",
        "path": "/auth/login",
        "headers": {"User-Agent": "Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36"},
    },
    {
        "method": "GET",
        "path": "/portal/admin",
        "headers": {"User-Agent": "Mozilla/5.0 zgrab/0.x"},
    },
    {
        "method": "POST",
        "path": "/login",
        "headers": {"User-Agent": "sqlmap/1.8"},
        "data": {"username": "admin'--", "password": "anything", "recovery_code": "MFA-BYPASS"},
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


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--host")
    parser.add_argument("--port", type=int)
    parser.add_argument("--pause-min", type=float, default=0.2)
    parser.add_argument("--pause-max", type=float, default=0.8)
    return parser.parse_args()


def resolve_base_url(base_url: str, host: str | None, port: int | None) -> str:
    if host is None and port is None:
        return base_url.rstrip("/")
    scheme, remainder = base_url.split("://", 1)
    current_host_port = remainder.split("/", 1)[0]
    current_host = current_host_port.split(":", 1)[0]
    resolved_host = host or current_host
    resolved_port = port if port is not None else int(current_host_port.split(":", 1)[1])
    return f"{scheme}://{resolved_host}:{resolved_port}"


def run_once(session: requests.Session, base_url: str, attack: dict[str, Any]) -> None:
    method = attack["method"]
    url = f"{base_url}{attack['path']}"
    profile = random.choice(ATTACKER_PROFILES)
    headers = dict(profile)
    headers.update(attack.get("headers", {}))
    response = session.request(
        method=method,
        url=url,
        headers=headers,
        params=attack.get("params"),
        data=attack.get("data"),
        json=attack.get("json"),
        timeout=5,
    )
    print(f"{headers['X-Forwarded-For']} {method} {attack['path']} -> {response.status_code}")


def simulate_session(base_url: str = DEFAULT_BASE_URL, pause_min: float = 0.2, pause_max: float = 0.8) -> None:
    session = requests.Session()
    for attack in ATTACKS:
        run_once(session, base_url, attack)
        time.sleep(random.uniform(pause_min, pause_max))


def main() -> None:
    args = parse_args()
    if args.pause_min < 0 or args.pause_max < 0 or args.pause_min > args.pause_max:
        raise SystemExit("pause range is invalid")
    base_url = resolve_base_url(args.base_url, args.host, args.port)
    simulate_session(base_url=base_url, pause_min=args.pause_min, pause_max=args.pause_max)
    print(f"Simulation complete. Review {base_url}/dashboard")


if __name__ == "__main__":
    main()
