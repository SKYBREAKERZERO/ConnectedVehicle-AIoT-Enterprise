"""Bounded ECS scale-in protection around one durable Worker batch.

Protect BEFORE claiming outbox rows or receiving an SQS message. Release after
the batch finishes or fails. Task protection does not replace DB leases,
idempotency, SQS redelivery or SIGTERM; it only handles ECS scale-in/deployments.
"""

from __future__ import annotations

import asyncio
import ipaddress
import json
import os
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager, suppress
from urllib.parse import urlsplit
from urllib.request import ProxyHandler, Request, build_opener

from enterprise_platform.config.environment import CloudRuntime
from enterprise_platform.config.settings import Settings

TTL_MINUTES = 10
RENEW_SECONDS = 60
HTTP_TIMEOUT_SECONDS = 3


class TaskProtectionError(RuntimeError):
    """A failed ECS protection transition must stop Worker intake."""


def _agent_endpoint(raw: str | None) -> str:
    if not raw:
        raise TaskProtectionError("ECS_AGENT_URI missing; refusing AWS Worker intake")
    url = urlsplit(raw)
    try:
        host = ipaddress.ip_address(url.hostname or "")
        port = url.port
    except ValueError as exc:
        raise TaskProtectionError("ECS_AGENT_URI must use a local agent IP") from exc
    if (
        url.scheme != "http"
        or not (host.is_link_local or host.is_loopback)
        or url.username is not None
        or url.password is not None
        or url.query
        or url.fragment
        or url.path not in {"", "/"}
        or (port is not None and not 1 <= port <= 65535)
    ):
        raise TaskProtectionError("ECS_AGENT_URI cannot address a remote service")
    return raw.rstrip("/") + "/task-protection/v1/state"


def _put_protection(endpoint: str, enabled: bool) -> None:
    body: dict[str, bool | int] = {"ProtectionEnabled": enabled}
    if enabled:
        body["ExpiresInMinutes"] = TTL_MINUTES
    request = Request(
        endpoint,
        data=json.dumps(body, separators=(",", ":")).encode("utf-8"),
        headers={"Content-Type": "application/json"},
        method="PUT",
    )
    # Agent traffic must never be sent through an HTTPS_PROXY or similar proxy.
    opener = build_opener(ProxyHandler({}))
    try:
        with opener.open(request, timeout=HTTP_TIMEOUT_SECONDS) as response:
            result = json.load(response)
    except (OSError, ValueError) as exc:
        raise TaskProtectionError("ECS task protection agent request failed") from exc
    if (
        not isinstance(result, dict)
        or not isinstance(result.get("protection"), dict)
        or result["protection"].get("ProtectionEnabled") is not enabled
        or not isinstance(result["protection"].get("TaskArn"), str)
        or not result["protection"]["TaskArn"].startswith("arn:aws:ecs:")
    ):
        raise TaskProtectionError("ECS agent did not confirm task protection transition")


@asynccontextmanager
async def protect_worker_batch(settings: Settings) -> AsyncIterator[None]:
    """Never claim work on AWS unless ECS confirms scale-in protection first."""
    if settings.cloud_runtime is not CloudRuntime.AWS:
        yield
        return

    endpoint = _agent_endpoint(os.environ.get("ECS_AGENT_URI"))
    await asyncio.to_thread(_put_protection, endpoint, True)
    renewal_failure: TaskProtectionError | None = None

    async def renew() -> None:
        nonlocal renewal_failure
        while True:
            await asyncio.sleep(RENEW_SECONDS)
            try:
                await asyncio.to_thread(_put_protection, endpoint, True)
            except TaskProtectionError as exc:
                renewal_failure = exc
                return

    task = asyncio.create_task(renew(), name="ecs-task-protection-renewal")
    try:
        yield
    finally:
        task.cancel()
        with suppress(asyncio.CancelledError):
            await task
        # On failure, a finite TTL bounds protection even if removal fails.
        await asyncio.to_thread(_put_protection, endpoint, False)
        if renewal_failure is not None:
            raise TaskProtectionError("ECS task protection renewal failed; stop intake") from (
                renewal_failure
            )
