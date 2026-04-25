from __future__ import annotations

import argparse
import random
import sys
import time
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

import requests  # noqa: E402

from honeypot.config import (  # noqa: E402
    ATTACKER_ARCHETYPES,
    ATTACKER_GEO_PROFILES,
    ATTACKER_PAYLOADS,
    ATTACKER_USER_AGENTS,
    DECOY_PAYMENT_RECORDS,
)

DEFAULT_BASE_URL = "http://127.0.0.1:5000"


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--host")
    parser.add_argument("--port", type=int)
    parser.add_argument("--pause-min", type=float, default=0.2)
    parser.add_argument("--pause-max", type=float, default=0.8)
    parser.add_argument("--archetype", choices=sorted(ATTACKER_ARCHETYPES.keys()), default="random")
    parser.add_argument("--seed", type=int)
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


def choose_user_agent(group_names: list[str]) -> str:
    selected_group = random.choice(group_names)
    return random.choice(ATTACKER_USER_AGENTS[selected_group])


def build_attack(action: str, profile: dict[str, str], archetype_key: str) -> dict[str, Any]:
    headers = dict(profile)
    user_agent_group = ATTACKER_ARCHETYPES[archetype_key]["user_agent_group"]
    headers["User-Agent"] = choose_user_agent(user_agent_group)
    if action == "landing":
        return {"method": "GET", "path": "/", "headers": headers}
    if action == "auth_page":
        return {"method": "GET", "path": "/auth/login", "headers": headers}
    if action == "admin_portal":
        return {"method": "GET", "path": "/portal/admin", "headers": headers}
    if action == "login":
        payload = {
            "username": random.choice(ATTACKER_PAYLOADS["login_usernames"]),
            "password": random.choice(ATTACKER_PAYLOADS["login_passwords"]),
            "recovery_code": random.choice(["MFA-BYPASS", "OTP-RESET", "", "RECOVERY-777"]),
        }
        return {"method": "POST", "path": "/login", "headers": headers, "data": payload}
    if action == "search":
        return {
            "method": "GET",
            "path": "/api/payments/search",
            "headers": headers,
            "params": {"q": random.choice(ATTACKER_PAYLOADS["search_queries"])},
        }
    if action == "card_lookup":
        return {
            "method": "GET",
            "path": "/api/cards/lookup",
            "headers": headers,
            "params": {"last4": random.choice(ATTACKER_PAYLOADS["card_last4"])},
        }
    if action == "refund":
        headers["Content-Type"] = "application/json"
        target_record = random.choice(DECOY_PAYMENT_RECORDS)
        return {
            "method": "POST",
            "path": "/api/transactions/refund",
            "headers": headers,
            "json": {
                "reference": target_record["record_id"],
                "amount": str(random.choice(["74.20", "219.94", "9999", "0.01", "1499.50"])),
                "note": random.choice(ATTACKER_PAYLOADS["refund_notes"]),
            },
        }
    if action == "export":
        return {"method": "GET", "path": "/admin/export", "headers": headers}
    raise ValueError(f"unsupported attack action: {action}")


def build_attack_plan(archetype_key: str) -> tuple[str, dict[str, str], list[dict[str, Any]]]:
    if archetype_key == "random":
        concrete_keys = [key for key in ATTACKER_ARCHETYPES.keys() if key != "random"]
        selected_key = random.choice(concrete_keys)
    else:
        selected_key = archetype_key
    profile = dict(random.choice(ATTACKER_GEO_PROFILES))
    sequence = ATTACKER_ARCHETYPES[selected_key]["sequence"]
    attacks = [build_attack(action, profile, selected_key) for action in sequence]
    return selected_key, profile, attacks


def run_once(session: requests.Session, base_url: str, attack: dict[str, Any]) -> None:
    method = attack["method"]
    url = f"{base_url}{attack['path']}"
    headers = dict(attack.get("headers", {}))
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


def simulate_session(
    base_url: str = DEFAULT_BASE_URL,
    pause_min: float = 0.2,
    pause_max: float = 0.8,
    archetype: str = "random",
    seed: int | None = None,
) -> None:
    if seed is not None:
        random.seed(seed)
    session = requests.Session()
    selected_archetype, profile, attacks = build_attack_plan(archetype)
    selected_name = profile.get("label", profile["X-Forwarded-For"])
    print(f"Simulating attacker profile: {selected_name} using archetype={selected_archetype}")
    for attack in attacks:
        run_once(session, base_url, attack)
        time.sleep(random.uniform(pause_min, pause_max))


def main() -> None:
    args = parse_args()
    if args.pause_min < 0 or args.pause_max < 0 or args.pause_min > args.pause_max:
        raise SystemExit("pause range is invalid")
    base_url = resolve_base_url(args.base_url, args.host, args.port)
    simulate_session(
        base_url=base_url,
        pause_min=args.pause_min,
        pause_max=args.pause_max,
        archetype=args.archetype,
        seed=args.seed,
    )
    print(f"Simulation complete. Review {base_url}/dashboard")


if __name__ == "__main__":
    main()
