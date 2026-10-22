"""Copy to tests/unit/iac/test_ota_storage_policy.py AFTER integrating the helper."""

from __future__ import annotations

from copy import deepcopy
from typing import Any

import pytest

from scripts.iac.plan_policy import evaluate, ota_storage_errors

BUCKET = "cv-ota-contract"
TYPES = (
    "aws_s3_bucket_versioning",
    "aws_s3_bucket_public_access_block",
    "aws_s3_bucket_ownership_controls",
)


def inventory() -> list[dict[str, Any]]:
    items = {
        "aws_s3_bucket": {"id": BUCKET, "force_destroy": False},
        TYPES[0]: {"bucket": BUCKET, "versioning_configuration": [{"status": "Enabled"}]},
        TYPES[1]: {
            "bucket": BUCKET,
            **dict.fromkeys(
                (
                    "block_public_acls",
                    "ignore_public_acls",
                    "block_public_policy",
                    "restrict_public_buckets",
                ),
                True,
            ),
        },
        TYPES[2]: {"bucket": BUCKET, "rule": [{"object_ownership": "BucketOwnerEnforced"}]},
        "aws_s3_bucket_server_side_encryption_configuration": {
            "bucket": BUCKET,
            "rule": [{"apply_server_side_encryption_by_default": [{"sse_algorithm": "aws:kms"}]}],
        },
    }
    return [
        {"address": f"{kind}.ota", "type": kind, "mode": "managed", "values": values}
        for kind, values in items.items()
    ]


def document(items: list[dict[str, Any]]) -> dict[str, Any]:
    return {
        "format_version": "1.2",
        "complete": True,
        "planned_values": {"root_module": {"resources": items}},
        "resource_changes": [],
    }


def test_secure_storage_passes_resolved_gate() -> None:
    assert not ota_storage_errors(inventory())
    assert not evaluate(document(inventory()))


@pytest.mark.parametrize("kind", TYPES)
def test_missing_or_mismatched_control_fails(kind: str) -> None:
    items = inventory()
    assert evaluate(document([item for item in items if item["type"] != kind]))
    control = next(item for item in items if item["type"] == kind)
    control["values"]["bucket"] = "other-bucket"
    assert evaluate(document(items))


@pytest.mark.parametrize(
    "flag",
    (
        "block_public_acls",
        "ignore_public_acls",
        "block_public_policy",
        "restrict_public_buckets",
    ),
)
@pytest.mark.parametrize("bad", (False, None, "true"))
def test_public_protections_require_exact_true(flag: str, bad: Any) -> None:
    items = inventory()
    items[2]["values"][flag] = bad
    assert evaluate(document(items))


def test_version_suspension_and_ownership_change_fail() -> None:
    items = inventory()
    items[1]["values"]["versioning_configuration"][0]["status"] = "Suspended"
    assert evaluate(document(items))
    items = inventory()
    items[3]["values"]["rule"][0]["object_ownership"] = "ObjectWriter"
    assert evaluate(document(items))


def test_force_destroy_and_unknown_bucket_fail() -> None:
    for value in (True, None):
        items = inventory()
        items[0]["values"]["force_destroy"] = value
        assert evaluate(document(items))
    items = inventory()
    items[0]["values"]["id"] = None
    assert evaluate(document(items))


def test_encryption_and_unknown_types_still_fail() -> None:
    assert evaluate(document(inventory()[:-1]))
    items = deepcopy(inventory())
    items.append({"address": "unreviewed.x", "type": "unreviewed", "values": {}})
    assert evaluate(document(items))
