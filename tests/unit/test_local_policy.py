from typing import Any

import pytest

from scripts.local_policy import permitted


def test_context_is_required_and_explicit_deny_wins() -> None:
    allow = {
        "Effect": "Allow",
        "Action": "kms:Decrypt",
        "Resource": "key-a",
        "Condition": {"StringEquals": {"SecretARN": "secret-a"}},
    }
    document: dict[str, Any] = {"Version": "2012-10-17", "Statement": [allow]}
    assert permitted(document, "kms:Decrypt", "key-a", {"SecretARN": "secret-a"})
    assert not permitted(document, "kms:Decrypt", "key-a", {})
    assert not permitted(document, "kms:Decrypt", "key-a", {"SecretARN": "secret-b"})
    assert not permitted(document, "kms:Decrypt", "key-b", {"SecretARN": "secret-a"})
    document["Statement"].append(allow | {"Effect": "Deny"})
    assert not permitted(document, "kms:Decrypt", "key-a", {"SecretARN": "secret-a"})


@pytest.mark.parametrize(
    "change",
    [
        {"Resource": "*"},
        {"Action": "kms:*"},
        {"NotResource": "key-b"},
        {"Condition": {"StringLike": {"SecretARN": "*"}}},
    ],
)
def test_unknown_or_wildcard_policy_is_rejected(change: dict[str, object]) -> None:
    document = {
        "Version": "2012-10-17",
        "Statement": [{"Effect": "Allow", "Action": "kms:Decrypt", "Resource": "key-a"} | change],
    }
    with pytest.raises(ValueError):
        permitted(document, "kms:Decrypt", "key-a", {})
