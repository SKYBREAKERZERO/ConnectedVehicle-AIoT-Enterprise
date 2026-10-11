from __future__ import annotations

import argparse
import json
import logging
from pathlib import Path

from enterprise_platform.runtime.process import run_async
from simulators.gateway.service import GatewayStore, serve


def main() -> None:
    parser = argparse.ArgumentParser(description="Independent simulated CAN Gateway ECU.")
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--port", type=int, default=19002)
    parser.add_argument("--tbox-port", type=int, default=19000)
    parser.add_argument("--body-bus-port", type=int, default=19003)
    parser.add_argument("--body-port", type=int, default=19001)
    parser.add_argument("--crash-after-route", action="store_true")
    parser.add_argument("--inspect", action="store_true")
    parser.add_argument("--limit", type=int, default=1000)
    parser.add_argument("--offset", type=int, default=0)
    args = parser.parse_args()
    if not 1 <= args.limit <= 1000 or args.offset < 0:
        parser.error("Inspection limit must be 1..1000 and offset nonnegative.")
    if len({args.port, args.tbox_port, args.body_bus_port, args.body_port}) != 4:
        parser.error("All virtual CAN ports must be different.")
    ports = (args.port, args.tbox_port, args.body_bus_port, args.body_port)
    if any(not 1 <= port <= 65535 for port in ports) or len(set(ports)) != len(ports):
        parser.error("Virtual CAN ports must be distinct and between 1 and 65535.")
    logging.basicConfig(level=logging.INFO)
    if args.inspect:
        if not args.database.is_file():
            parser.error("Gateway SQLite file does not exist.")
        store = GatewayStore(args.database)
        try:
            print(json.dumps(store.reconcile(limit=args.limit, offset=args.offset), indent=2))
        finally:
            store.close()
    else:
        run_async(
            lambda: serve(
                args.database,
                args.port,
                args.tbox_port,
                args.body_bus_port,
                args.body_port,
                args.crash_after_route,
            )
        )


if __name__ == "__main__":
    main()
