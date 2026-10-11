"""Deliver durable vehicle ACK and ECU result events through the existing HTTP API.

The API response confirms the server processed the report, *not* that the ECU
executed. Network ambiguity is resolved by retrying the exact persisted event_id
and JSON body. The transport is injected (normally httpx2.AsyncClient).
"""

from __future__ import annotations

import asyncio
import logging
from collections.abc import Callable, Mapping
from dataclasses import dataclass
from datetime import UTC, datetime
from email.utils import parsedate_to_datetime
from math import ceil, isfinite
from random import SystemRandom
from re import fullmatch
from typing import Protocol

from simulators.vehicle_device.execution_store import DeviceExecutionStore, LeasedReport


class HTTPResponse(Protocol):
    @property
    def status_code(self) -> int: ...

    @property
    def headers(self) -> Mapping[str, str]: ...

    def json(self) -> object: ...


class HTTPClient(Protocol):
    async def post(
        self, url: str, *, headers: Mapping[str, str], json: Mapping[str, object]
    ) -> HTTPResponse: ...


@dataclass(frozen=True, slots=True)
class DeliverySummary:
    claimed: int = 0
    delivered: int = 0
    deferred: int = 0
    blocked: int = 0


def _transport_exceptions() -> tuple[type[Exception], ...]:
    """Include the project's httpx2 transport errors without requiring it in unit tests."""
    try:
        import httpx2
    except ImportError:
        return (TimeoutError, OSError)
    return (TimeoutError, OSError, httpx2.TransportError)


logger = logging.getLogger(__name__)

MAX_RETRY_AFTER_SECONDS = 86_400


class DeviceResultReporter:
    def __init__(
        self,
        *,
        store: DeviceExecutionStore,
        client: HTTPClient,
        token_supplier: Callable[[], str],
        transport_errors: tuple[type[Exception], ...] | None = None,
        random_unit: Callable[[], float] | None = None,
    ) -> None:
        self._store = store
        self._client = client
        self._token_supplier = token_supplier
        self._transport_errors = (
            transport_errors if transport_errors is not None else _transport_exceptions()
        )
        # Pass a deterministic generator for tests; production uses independent OS randomness.
        self._random_unit = random_unit if random_unit is not None else SystemRandom().random

    def _delay(self, attempt: int) -> int:
        """Equal jitter: random wait in [base/2, base), rounded up to whole seconds.

        `attempt` counts durable SQLite leases, starting at one. The upper
        exponential bound is 60 seconds. The lease and result are persisted.
        """
        base = min(60, 1 << min(max(attempt - 1, 0), 6))
        unit = self._random_unit()
        if not isfinite(unit) or not 0.0 <= unit < 1.0:
            raise ValueError("random_unit must yield finite floats in [0, 1)")
        return ceil(base * (0.5 + 0.5 * unit))

    @staticmethod
    def _retry_after_seconds(headers: Mapping[str, str], *, now: datetime) -> int | None:
        """Parse Retry-After delta-seconds or an RFC-style HTTP-date, if valid.

        Past dates mean zero additional server wait. No assumptions are made
        about a trustworthy wall clock; NTP or a monotonic-aware scheduler is
        required in production for strict date-based deadline semantics.
        """
        raw = next(
            (value for key, value in headers.items() if key.lower() == "retry-after"),
            None,
        )
        if raw is None or not 1 <= len(raw) <= 128:
            return None
        raw = raw.strip()
        if fullmatch(r"[0-9]+", raw):
            return int(raw)
        try:
            deadline = parsedate_to_datetime(raw)
        except (TypeError, ValueError, OverflowError):
            return None
        if deadline.tzinfo is None:
            return None
        return max(0, ceil((deadline - now).total_seconds()))

    async def flush_once(self, *, limit: int = 10, now: datetime | None = None) -> DeliverySummary:
        """Send at most one finite batch; caller schedules subsequent invocations."""
        reports = await asyncio.to_thread(self._store.lease_reports, limit=limit, now=now)
        delivered = deferred = blocked = 0
        for report in reports:
            outcome = await self._deliver(report, now=now)
            if outcome == "delivered":
                delivered += 1
            elif outcome == "deferred":
                deferred += 1
            else:
                blocked += 1
        return DeliverySummary(len(reports), delivered, deferred, blocked)

    async def _deliver(self, report: LeasedReport, *, now: datetime | None) -> str:
        path = f"/vehicles/{report.vehicle_id}/commands/{report.command_id}/reports"
        try:
            token = self._token_supplier().strip()
        except (OSError, ValueError):
            token = ""
        if not token or len(token) > 8192 or not token.isascii() or "\r" in token or "\n" in token:
            await asyncio.to_thread(
                self._store.defer,
                report,
                retry_after_seconds=self._delay(7),
                error_code="TOKEN_UNAVAILABLE",
                now=now,
            )
            return "deferred"
        try:
            response = await self._client.post(
                path,
                headers={"Authorization": f"Bearer {token}", "Content-Type": "application/json"},
                json=report.payload,
            )
        except self._transport_errors:
            await self._retry(report, "NETWORK_FAILURE", now=now)
            return "deferred"
        status = response.status_code
        # Never treat redirects as transient network failures: the device report
        # endpoint and its credential-bearing origin must be provisioned explicitly.
        # Keep the original outbox event for operator reconciliation.
        if 300 <= status < 400:
            await asyncio.to_thread(self._store.block, report, error_code="HTTP_REDIRECT_BLOCKED")
            return "blocked"
        if status == 200:
            try:
                data = response.json()
                valid = (
                    isinstance(data, dict)
                    and data.get("command_id") == report.command_id
                    and data.get("status") in {"acknowledged", "succeeded", "failed"}
                    and (report.status == "acknowledged" or data.get("status") == report.status)
                )
            except (ValueError, TypeError):
                valid = False
            if not valid:
                await asyncio.to_thread(
                    self._store.block, report, error_code="INVALID_SERVER_RESPONSE"
                )
                return "blocked"
            await asyncio.to_thread(self._store.mark_delivered, report)
            return "delivered"
        if status in {408, 429} or 500 <= status <= 599:
            retry_after = self._retry_after_seconds(
                getattr(response, "headers", {}), now=now or datetime.now(UTC)
            )
            # Never cap a valid server deadline then retry too early. Very long
            # deadlines require an operator decision instead of unbounded retries.
            if retry_after is not None and retry_after > MAX_RETRY_AFTER_SECONDS:
                await asyncio.to_thread(
                    self._store.block, report, error_code="HTTP_RETRY_AFTER_TOO_LONG"
                )
                return "blocked"
            await self._retry(report, "HTTP_RETRYABLE", now=now, retry_after=retry_after)
            return "deferred"
        if status in (401, 403):
            logger.error("device_report_auth_blocked requires_credential_repair_and_audited_replay")
        # Do not log response bodies or blindly retry authentication/business conflicts.
        await asyncio.to_thread(self._store.block, report, error_code=f"HTTP_{status}")
        return "blocked"

    async def _retry(
        self,
        report: LeasedReport,
        reason: str,
        *,
        now: datetime | None,
        retry_after: int | None = None,
    ) -> None:
        # Server Retry-After is a lower bound. Our jitter can be longer, never shorter.
        wait = max(self._delay(report.attempt), retry_after or 0)
        await asyncio.to_thread(
            self._store.defer,
            report,
            retry_after_seconds=wait,
            error_code=reason,
            now=now,
        )
