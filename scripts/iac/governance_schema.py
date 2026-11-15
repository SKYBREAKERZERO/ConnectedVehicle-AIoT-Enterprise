"""Validate the real provider schema used by governance contracts."""

from __future__ import annotations

from typing import Any


def require_governance_schema(schema: dict[str, Any]) -> None:
    try:
        provider = schema["provider_schemas"]["registry.terraform.io/hashicorp/aws"]
        attributes = provider["data_source_schemas"]["aws_organizations_organization"]["block"][
            "attributes"
        ]
        roots = attributes["roots"]["type"][1][1]
        fields = roots["policy_types"][1][1]
        if fields.get("type") != "string" or fields.get("status") != "string":
            raise ValueError("Unexpected Organizations policy_types schema")
    except (KeyError, TypeError, IndexError, AttributeError) as exc:
        raise ValueError("Organizations provider schema contract changed") from exc
