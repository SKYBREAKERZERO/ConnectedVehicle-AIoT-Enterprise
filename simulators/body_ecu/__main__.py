from __future__ import annotations

import argparse
import asyncio
import json
import logging
import os
from pathlib import Path

from enterprise_platform.runtime.process import run_async, termination_signals
from simulators.body_ecu.service import BodyStore
from simulators.vehicle_device.can import VirtualCAN
from simulators.vehicle_device.ownership import runtime_lock


async def _serve(database: Path, port: int, gateway_port: int, crash: bool) -> None:
    store = BodyStore(database)
    try:
        bus = VirtualCAN(port, gateway_port)
    except BaseException:
        store.close()
        raise
    stop = asyncio.Event()
    try:
        with termination_signals(stop):
            logging.info("body_ecu_ready")
            while not stop.is_set():
                try:
                    async with asyncio.timeout(0.2):
                        frame = await bus.receive()
                    result = store.execute(frame)
                    if crash and store.consume_fault():
                        os._exit(71)
                    await bus.send(result)
                except TimeoutError:
                    continue
                except ValueError:
                    logging.warning("body_ecu_invalid_frame")
    finally:
        bus.close()
        store.close()
        logging.info("body_ecu_stopped")


async def serve(database: Path, port: int, gateway_port: int, crash: bool) -> None:
    with runtime_lock(database, wait_seconds=1):
        await _serve(database, port, gateway_port, crash)


def main() -> None:
    parser = argparse.ArgumentParser(description="Independent simulated Body ECU (loopback CAN).")
    parser.add_argument("--database", type=Path, required=True)
    parser.add_argument("--port", type=int, default=19001)
    parser.add_argument("--gateway-port", type=int, default=19003)
    parser.add_argument("--crash-after-execution", action="store_true")
    parser.add_argument("--inspect", action="store_true")
    parser.add_argument("--limit", type=int, default=1000)
    parser.add_argument("--offset", type=int, default=0)
    args = parser.parse_args()
    if not 1 <= args.limit <= 1000 or args.offset < 0:
        parser.error("Inspection limit must be 1..1000 and offset nonnegative.")
    ports = (args.port, args.gateway_port)
    if any(not 1 <= port <= 65535 for port in ports) or len(set(ports)) != len(ports):
        parser.error("Virtual CAN ports must be distinct and between 1 and 65535.")
    logging.basicConfig(level=logging.INFO)
    if args.inspect:
        if not args.database.is_file():
            parser.error("Body ECU SQLite file does not exist.")
        store = BodyStore(args.database)
        try:
            print(json.dumps(store.reconcile(limit=args.limit, offset=args.offset), indent=2))
        finally:
            store.close()
        return
    run_async(
        lambda: serve(args.database, args.port, args.gateway_port, args.crash_after_execution)
    )


if __name__ == "__main__":
    main()
