"""ECS scale-in must never delete Worker services or claim work unprotected."""

from __future__ import annotations

import asyncio
from pathlib import Path
from typing import Any

import pytest

from enterprise_platform.config.environment import CloudRuntime
from enterprise_platform.config.settings import Settings
from enterprise_platform.reliability import ecs_task_protection as protect

ROOT = Path(__file__).resolve().parents[2]


def test_worker_zero_replicas_preserves_terraform_resource_addresses() -> None:
    base = (ROOT / "infra/terraform/environments/ota-staging/worker_base.tf").read_text()
    service = (ROOT / "infra/terraform/environments/ota-staging/worker_service.tf").read_text()
    assert "worker_active = var.enable_service && var.enable_workers ? local.worker_kinds" in base
    assert "var.worker_desired_counts[kind] > 0" not in base
    assert "for_each                           = local.worker_active" in service
    assert "desired_count                      = var.worker_desired_counts[each.key]" in service
    assert "lifecycle { prevent_destroy = true }" in service
    assert 'var.worker_desired_counts[each.key] == 0' in service


def test_ecs_agent_endpoint_rejects_remote_or_redirectable_url() -> None:
    for uri in (
        None, "", "https://169.254.170.2", "http://evil.example.com",
        "http://169.254.170.2.evil.example.com", "http://10.0.0.5",
        "http://169.254.170.2/other", "http://169.254.170.2?foo=1",
        "http://127.0.0.1@evil.example.com",
    ):
        with pytest.raises(protect.TaskProtectionError):
            protect._agent_endpoint(uri)
    assert protect._agent_endpoint("http://169.254.170.2") == (
        "http://169.254.170.2/task-protection/v1/state"
    )


@pytest.mark.asyncio
async def test_aws_worker_protects_before_claim_and_clears_after(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[str] = []
    monkeypatch.setenv("ECS_AGENT_URI", "http://169.254.170.2:51679")

    def set_protection(_endpoint: str, enabled: bool) -> None:
        seen.append("protect" if enabled else "release")

    monkeypatch.setattr(protect, "_put_protection", set_protection)
    settings = Settings.model_construct(cloud_runtime=CloudRuntime.AWS)
    async with protect.protect_worker_batch(settings):
        seen.append("claim_sqs_or_outbox")
    assert seen == ["protect", "claim_sqs_or_outbox", "release"]


@pytest.mark.asyncio
async def test_failed_protection_rejects_work_intake(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.setenv("ECS_AGENT_URI", "http://169.254.170.2")
    ran = False

    def failed(_endpoint: str, _enabled: bool) -> None:
        raise protect.TaskProtectionError("control plane unavailable")

    monkeypatch.setattr(protect, "_put_protection", failed)
    with pytest.raises(protect.TaskProtectionError):
        async with protect.protect_worker_batch(
            Settings.model_construct(cloud_runtime=CloudRuntime.AWS)
        ):
            ran = True
    assert ran is False


@pytest.mark.asyncio
async def test_unhandled_work_error_still_releases_task(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    seen: list[bool] = []
    monkeypatch.setenv("ECS_AGENT_URI", "http://169.254.170.2")
    monkeypatch.setattr(
        protect, "_put_protection", lambda _endpoint, enabled: seen.append(enabled)
    )
    with pytest.raises(RuntimeError, match="work failed"):
        async with protect.protect_worker_batch(
            Settings.model_construct(cloud_runtime=CloudRuntime.AWS)
        ):
            raise RuntimeError("work failed")
    assert seen == [True, False]


@pytest.mark.asyncio
async def test_bounded_renewal_failure_stops_next_batch(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    enabled = 0
    transitions: list[bool] = []
    monkeypatch.setenv("ECS_AGENT_URI", "http://169.254.170.2")
    monkeypatch.setattr(protect, "RENEW_SECONDS", 0.001)

    def fail_renew(_endpoint: str, state: bool) -> None:
        nonlocal enabled
        transitions.append(state)
        if state:
            enabled += 1
            if enabled > 1:
                raise protect.TaskProtectionError("renewal unavailable")

    monkeypatch.setattr(protect, "_put_protection", fail_renew)
    with pytest.raises(protect.TaskProtectionError, match="renewal failed"):
        async with protect.protect_worker_batch(
            Settings.model_construct(cloud_runtime=CloudRuntime.AWS)
        ):
            await asyncio.sleep(0.05)
    assert transitions[0] is True
    assert transitions[-1] is False


@pytest.mark.asyncio
async def test_localstack_does_not_call_ecs_agent(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    monkeypatch.delenv("ECS_AGENT_URI", raising=False)

    def should_never_be_called(*args: Any) -> None:
        pytest.fail("local runtime must not call ECS")

    monkeypatch.setattr(protect, "_put_protection", should_never_be_called)
    async with protect.protect_worker_batch(
        Settings.model_construct(cloud_runtime=CloudRuntime.LOCALSTACK)
    ):
        pass


def test_entrypoints_guard_all_work_claim_operations() -> None:
    for name, operation in (
        ("apps/outbox_worker/main.py", "await dispatcher.dispatch_batch()"),
        ("apps/remote_command_worker/main.py", "await worker.run_once()"),
        ("apps/campaign/__main__.py", "await campaigns.dispatch("),
    ):
        body = (ROOT / name).read_text()
        assert "async with protect_worker_batch(settings):" in body
        assert operation in body
    iam = (ROOT / "infra/terraform/environments/ota-staging/worker_iam.tf").read_text()
    assert 'actions   = ["ecs:GetTaskProtection", "ecs:UpdateTaskProtection"]' in iam
    assert 'variable = "ecs:cluster"' in iam
