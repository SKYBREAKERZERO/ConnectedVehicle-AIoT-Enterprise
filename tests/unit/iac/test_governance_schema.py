from __future__ import annotations

from typing import Any

import pytest

from scripts.iac.governance_schema import require_governance_schema


def schema(fields: dict[str, str]) -> dict[str, Any]:
    return {
        "provider_schemas": {
            "registry.terraform.io/hashicorp/aws": {
                "data_source_schemas": {
                    "aws_organizations_organization": {
                        "block": {
                            "attributes": {
                                "roots": {
                                    "type": [
                                        "list",
                                        ["object", {"policy_types": ["list", ["object", fields]]}],
                                    ]
                                }
                            }
                        }
                    }
                }
            }
        }
    }


def test_provider_policy_type_uses_type_and_status() -> None:
    require_governance_schema(schema({"type": "string", "status": "string"}))


@pytest.mark.parametrize("fields", [{"name": "string", "status": "string"}, {"type": "string"}, {}])
def test_changed_or_fabricated_provider_fields_fail_closed(fields: dict[str, str]) -> None:
    with pytest.raises(ValueError):
        require_governance_schema(schema(fields))
