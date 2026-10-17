"""Bounded recovery telemetry; identifiers belong in events, never metric labels."""

from __future__ import annotations

import json
import logging
import re
import threading
from collections import deque
from collections.abc import Iterator
from contextlib import contextmanager, suppress
from contextvars import ContextVar
from dataclasses import asdict, dataclass
from datetime import UTC, datetime
from uuid import uuid4

from prometheus_client import CollectorRegistry, Counter

from enterprise_platform.observability.context import get_observability_context

STATES = frozenset(
    {
        "RUNNING",
        "FAULT_DETECTED",
        "CLASSIFIED",
        "RETRY",
        "RECONCILE",
        "QUARANTINE",
        "VERIFY",
        "RECOVERED",
        "ESCALATED",
    }
)
COMPONENTS = frozenset({"database", "worker", "demo"})
logger = logging.getLogger(__name__)


@dataclass(frozen=True)
class RecoveryContext:
    operation_id: str
    fault_id: str
    component: str


_context: ContextVar[RecoveryContext | None] = ContextVar("recovery_context", default=None)


class RecoveryMonitor:
    def __init__(self) -> None:
        self.registry = CollectorRegistry()
        self.transitions = Counter(
            "vehicle_recovery_transitions_total",
            "Recovery state observations",
            ["component", "state"],
            registry=self.registry,
        )
        self._events: deque[dict[str, object]] = deque(maxlen=1024)
        self._lock = threading.Lock()
        self._sequence = 0

    def record(self, context: RecoveryContext, state: str, attempt: int, code: str | None) -> None:
        if (
            state not in STATES
            or context.component not in COMPONENTS
            or not 0 <= attempt <= 1000000
        ):
            raise ValueError("Invalid recovery observation")
        observability = get_observability_context()
        with self._lock:
            self._sequence += 1
            event: dict[str, object] = dict(
                asdict(context),
                sequence=self._sequence,
                state=state,
                attempt=attempt,
                sqlstate=code,
                time=datetime.now(UTC).isoformat(),
                request_id=observability.request_id,
                correlation_id=observability.correlation_id,
                trace_id=observability.trace_id,
            )
            self._events.append(event)
            self.transitions.labels(context.component, state).inc()
        with suppress(Exception):
            logger.warning("recovery_event %s", json.dumps(event, sort_keys=True))

    def snapshot(self) -> list[dict[str, object]]:
        with self._lock:
            return [dict(row) for row in self._events]


RECOVERY_MONITOR = RecoveryMonitor()
_monitor: ContextVar[RecoveryMonitor] = ContextVar("recovery_monitor", default=RECOVERY_MONITOR)


@contextmanager
def monitoring_session(monitor: RecoveryMonitor) -> Iterator[None]:
    token = _monitor.set(monitor)
    try:
        yield
    finally:
        _monitor.reset(token)


@contextmanager
def recovery_scope(
    component: str, *, operation_id: str | None = None, fault_id: str | None = None
) -> Iterator[RecoveryContext]:
    parent = _context.get()
    context = RecoveryContext(
        operation_id or (parent.operation_id if parent else uuid4().hex),
        fault_id or (parent.fault_id if parent else uuid4().hex),
        component,
    )
    if component not in COMPONENTS or any(
        re.fullmatch(r"[0-9a-f]{32,64}", value) is None
        for value in (context.operation_id, context.fault_id)
    ):
        raise ValueError("Recovery identities must be opaque hexadecimal IDs")
    token = _context.set(context)
    try:
        yield context
    finally:
        _context.reset(token)


def observe_recovery(state: str, attempt: int = 0, code: str | None = None) -> None:
    # Monitoring is best effort; acceptance separately verifies actual collection.
    with suppress(Exception):
        context = _context.get()
        if context is not None:
            _monitor.get().record(context, state, attempt, code)
