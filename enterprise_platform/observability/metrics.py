from __future__ import annotations

from secrets import compare_digest
from time import monotonic

from fastapi import FastAPI, HTTPException, Request, Response
from prometheus_client import (
    CONTENT_TYPE_LATEST,
    CollectorRegistry,
    Counter,
    Histogram,
    generate_latest,
)
from starlette.types import ASGIApp, Message, Receive, Scope, Send

from enterprise_platform.config.settings import Settings


class HTTPMetrics:
    def __init__(self) -> None:
        self.registry = CollectorRegistry()
        self.requests = Counter(
            "vehicle_http_requests_total",
            "HTTP requests",
            ["method", "route", "status"],
            registry=self.registry,
        )
        self.duration = Histogram(
            "vehicle_http_duration_seconds",
            "HTTP latency",
            ["method", "route"],
            registry=self.registry,
            buckets=(0.01, 0.05, 0.1, 0.25, 0.5, 1, 3, 10),
        )


class MetricsMiddleware:
    def __init__(self, app: ASGIApp, metrics: HTTPMetrics) -> None:
        self.app, self.metrics = app, metrics

    async def __call__(self, scope: Scope, receive: Receive, send: Send) -> None:
        if scope["type"] != "http" or scope.get("path") == "/metrics":
            await self.app(scope, receive, send)
            return
        started, status = monotonic(), 500

        async def capture(message: Message) -> None:
            nonlocal status
            if message["type"] == "http.response.start":
                status = message["status"]
            await send(message)

        try:
            await self.app(scope, receive, capture)
        finally:
            # Templates only: never raw vehicle IDs, tenant IDs or unmatched URLs.
            route = getattr(scope.get("route"), "path", "unmatched")
            method = scope.get("method", "OTHER")
            if method not in {"GET", "POST", "PUT", "PATCH", "DELETE", "HEAD", "OPTIONS"}:
                method = "OTHER"
            self.metrics.requests.labels(method, route, str(status)).inc()
            self.metrics.duration.labels(method, route).observe(monotonic() - started)


def configure_metrics(app: FastAPI, settings: Settings) -> HTTPMetrics:
    metrics = HTTPMetrics()
    app.add_middleware(MetricsMiddleware, metrics=metrics)

    @app.get("/metrics", include_in_schema=False)
    async def scrape(request: Request) -> Response:
        expected = settings.metrics_token
        scheme, _, token = request.headers.get("authorization", "").partition(" ")
        if (
            not expected
            or scheme.lower() != "bearer"
            or not compare_digest(token.encode(), expected.get_secret_value().encode())
        ):
            raise HTTPException(status_code=403, detail="Metrics access denied")
        return Response(
            generate_latest(metrics.registry), headers={"Content-Type": CONTENT_TYPE_LATEST}
        )

    return metrics
