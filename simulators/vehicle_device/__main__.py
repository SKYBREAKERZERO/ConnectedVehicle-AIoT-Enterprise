from __future__ import annotations

import argparse
import logging
from pathlib import Path

from enterprise_platform.runtime.process import run_async
from simulators.vehicle_device.config import DeviceSettings
from simulators.vehicle_device.runtime import serve
from simulators.vehicle_device.store import print_reconciliation


def main() -> None:
    parser = argparse.ArgumentParser(description="Independent T-Box simulator.")
    parser.add_argument("--reconcile", type=Path, metavar="SQLITE")
    parser.add_argument("--requeue-blocked", action="store_true")
    parser.add_argument("--event-id")
    parser.add_argument("--operation-id")
    parser.add_argument("--actor")
    parser.add_argument("--reason")
    parser.add_argument("--tenant-id")
    parser.add_argument("--vehicle-id")
    parser.add_argument("--limit", type=int, default=1000)
    parser.add_argument("--offset", type=int, default=0)
    args = parser.parse_args()
    if not 1 <= args.limit <= 1000 or args.offset < 0:
        parser.error("Reconciliation limit must be 1..1000 and offset nonnegative.")
    if args.requeue_blocked and args.reconcile is None:
        parser.error("--requeue-blocked requires --reconcile")
    metadata = (
        args.event_id,
        args.operation_id,
        args.actor,
        args.reason,
        args.tenant_id,
        args.vehicle_id,
    )
    if args.requeue_blocked and not all(metadata):
        parser.error(
            "Replay requires --event-id, --operation-id, --actor, --reason, "
            "--tenant-id and --vehicle-id."
        )
    if not args.requeue_blocked and any(value is not None for value in metadata):
        parser.error("Replay metadata requires --requeue-blocked.")
    logging.basicConfig(level=logging.INFO)
    if args.reconcile is not None:
        if not args.reconcile.is_file():
            parser.error("T-Box SQLite file does not exist.")
        print_reconciliation(
            args.reconcile,
            args.requeue_blocked,
            args.limit,
            args.offset,
            event_id=args.event_id,
            operation_id=args.operation_id,
            actor=args.actor,
            reason=args.reason,
            tenant_id=args.tenant_id,
            vehicle_id=args.vehicle_id,
        )
    else:
        settings = DeviceSettings()  # type: ignore[call-arg]  # Required values come from DEVICE_* env.
        run_async(lambda: serve(settings))


if __name__ == "__main__":
    main()
