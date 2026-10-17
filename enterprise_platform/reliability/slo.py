"""Explicit local drill SLOs; short canaries are not production availability claims."""

from __future__ import annotations

import math
from datetime import datetime
from typing import Literal, TypedDict

from pydantic import AwareDatetime, BaseModel, ConfigDict, Field, model_validator


class StrictEvidence(BaseModel):
    model_config = ConfigDict(
        extra="forbid", strict=True, allow_inf_nan=False, hide_input_in_errors=True
    )


class SLOPolicy(StrictEvidence):
    version: Literal[1]
    profile: Literal["local_drill"]
    readiness_availability: float = Field(ge=0.99, le=1)
    readiness_p95_seconds: float = Field(gt=0, le=1)
    recovery_seconds: float = Field(gt=0, le=30)
    minimum_requests: int = Field(ge=100, le=10000)
    maximum_evidence_age_seconds: int = Field(ge=60, le=900)


class Probe(StrictEvidence):
    status: int = Field(ge=0, le=599)
    elapsed_seconds: float = Field(ge=0, le=10)


class MetricsDelta(StrictEvidence):
    requests: int = Field(ge=0)
    errors: int = Field(ge=0)
    duration_count: int = Field(ge=0)


class CanaryWindow(StrictEvidence):
    window_id: str = Field(pattern=r"^[0-9a-f]{32}$")
    phase: Literal["fault", "recovered"]
    started_at: AwareDatetime
    ended_at: AwareDatetime
    route: Literal["/health/ready"]
    samples: list[Probe] = Field(min_length=1, max_length=10000)
    metrics_delta: MetricsDelta

    @model_validator(mode="after")
    def consistent(self) -> CanaryWindow:
        if self.ended_at < self.started_at:
            raise ValueError("Canary clock regressed")
        errors = sum(sample.status != 200 for sample in self.samples)
        if self.metrics_delta != MetricsDelta(
            requests=len(self.samples), errors=errors, duration_count=len(self.samples)
        ):
            raise ValueError("HTTP observations do not reconcile with API metrics")
        return self


class CanaryReport(StrictEvidence):
    version: Literal[1]
    profile: Literal["local_drill"]
    provenance: dict[str, str]
    readiness_sha256: str = Field(pattern=r"^[0-9a-f]{64}$")
    fault: CanaryWindow
    recovered: CanaryWindow
    connection_limit_restored: Literal[True]
    runtime_superuser: Literal[False]
    runtime_bypassrls: Literal[False]
    runtime_schema_create: Literal[False]
    real_aws_verified: Literal[False]

    @model_validator(mode="after")
    def ordered(self) -> CanaryReport:
        if (
            self.fault.phase != "fault"
            or self.recovered.phase != "recovered"
            or self.fault.window_id == self.recovered.window_id
            or self.recovered.started_at < self.fault.ended_at
        ):
            raise ValueError("Canary windows overlap or lose their fault history")
        return self


class SLODecision(TypedDict):
    decision: str
    checks: dict[str, bool]
    requests: int
    failures: int
    availability: float
    p95_seconds: float
    error_budget_requests: float


def evaluate_window(window: CanaryWindow, policy: SLOPolicy, *, now: datetime) -> SLODecision:
    total = len(window.samples)
    failures = sum(sample.status != 200 for sample in window.samples)
    available = (total - failures) / total
    p95 = sorted(sample.elapsed_seconds for sample in window.samples)[math.ceil(total * 0.95) - 1]
    age = (now - window.ended_at).total_seconds()
    span = (window.ended_at - window.started_at).total_seconds()
    checks = {
        "minimum_traffic": total >= policy.minimum_requests,
        "fresh_evidence": -5 <= age <= policy.maximum_evidence_age_seconds,
        "bounded_window": 0 <= span <= 120,
        "availability": available >= policy.readiness_availability,
        "latency": p95 <= policy.readiness_p95_seconds,
    }
    return {
        "decision": "proceed" if all(checks.values()) else "abort",
        "checks": checks,
        "requests": total,
        "failures": failures,
        "availability": available,
        "p95_seconds": p95,
        "error_budget_requests": total * (1 - policy.readiness_availability),
    }
