"""Evaluate the repository's small exact-resource policy subset for local matrices.

This is configuration regression evidence, not an AWS authorization emulator.
Unsupported statements are rejected, never interpreted as permission.
"""

from __future__ import annotations

from typing import Any


def permitted(
    document: dict[str, Any],
    action: str,
    resource: str,
    context: dict[str, str],
) -> bool:
    if document.get("Version") != "2012-10-17" or set(document) != {"Version", "Statement"}:
        raise ValueError("Unsupported local policy document")
    allowed = False
    denied = False
    for statement in document["Statement"]:
        if not {"Effect", "Action", "Resource"} <= set(statement) or set(statement) - {
            "Effect",
            "Action",
            "Resource",
            "Condition",
        }:
            raise ValueError("Unsupported local policy statement")
        if statement["Effect"] not in {"Allow", "Deny"}:
            raise ValueError("Unsupported local policy effect")
        for field in ("Action", "Resource"):
            if not isinstance(statement[field], str) or any(c in statement[field] for c in "*?"):
                raise ValueError("Local runtime policy requires exact action/resource")
        conditions = statement.get("Condition", {})
        if conditions and set(conditions) != {"StringEquals"}:
            raise ValueError("Unsupported local policy condition")
        required = conditions.get("StringEquals", {})
        if any(not isinstance(value, str) for value in required.values()):
            raise ValueError("Unsupported local condition value")
        matches = statement["Action"] == action and statement["Resource"] == resource
        matches = matches and all(context.get(key) == value for key, value in required.items())
        if matches:
            allowed |= statement["Effect"] == "Allow"
            denied |= statement["Effect"] == "Deny"
    return allowed and not denied
