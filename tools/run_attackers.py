from __future__ import annotations

import argparse
import random
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent))

from tools.simulate_attackers import DEFAULT_BASE_URL, resolve_base_url, simulate_session  # noqa: E402


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser()
    parser.add_argument("count", type=int, help="Number of attacker sessions to simulate")
    parser.add_argument("--base-url", default=DEFAULT_BASE_URL)
    parser.add_argument("--host")
    parser.add_argument("--port", type=int)
    parser.add_argument("--pause-min", type=float, default=0.3)
    parser.add_argument("--pause-max", type=float, default=1.2)
    parser.add_argument("--archetype", default="random")
    parser.add_argument("--seed", type=int)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    if args.count < 1:
        raise SystemExit("count must be at least 1")
    if args.pause_min < 0 or args.pause_max < 0 or args.pause_min > args.pause_max:
        raise SystemExit("pause range is invalid")
    base_url = resolve_base_url(args.base_url, args.host, args.port)
    for attacker_index in range(1, args.count + 1):
        print(f"Starting attacker session {attacker_index}/{args.count}")
        session_seed = None if args.seed is None else args.seed + attacker_index - 1
        simulate_session(
            base_url=base_url,
            pause_min=args.pause_min,
            pause_max=args.pause_max,
            archetype=args.archetype,
            seed=session_seed,
        )
        if attacker_index < args.count:
            time.sleep(random.uniform(args.pause_min, args.pause_max))
    print(f"Completed {args.count} attacker sessions. Review {base_url}/dashboard")


if __name__ == "__main__":
    main()
