from __future__ import annotations

from typing import Any, cast

from apps.api.main import create_app


def test_remote_command_openapi_contract() -> None:
    schema = create_app().openapi()

    paths = cast(
        dict[str, Any],
        schema["paths"],
    )

    operation = paths["/vehicles/{vehicle_id}/commands"]["post"]

    assert operation["operationId"] == "issueRemoteCommand"

    parameters = operation["parameters"]

    vehicle_parameter = next(
        parameter
        for parameter in parameters
        if (parameter["name"] == "vehicle_id" and parameter["in"] == "path")
    )

    assert vehicle_parameter["required"] is True
    assert vehicle_parameter["schema"]["format"] == "uuid"

    idempotency_parameter = next(
        parameter
        for parameter in parameters
        if (parameter["name"] == "Idempotency-Key" and parameter["in"] == "header")
    )

    assert idempotency_parameter["required"] is True

    assert idempotency_parameter["schema"]["minLength"] == 1

    assert idempotency_parameter["schema"]["maxLength"] == 255

    request_body = operation["requestBody"]

    assert request_body["required"] is True

    request_schema = request_body["content"]["application/json"]["schema"]

    assert request_schema["$ref"].endswith("/IssueRemoteCommandRequest")

    responses = operation["responses"]

    for status_code in (
        "202",
        "400",
        "401",
        "403",
        "404",
        "409",
        "422",
        "500",
    ):
        assert status_code in responses

    accepted_schema = responses["202"]["content"]["application/json"]["schema"]

    assert accepted_schema["$ref"].endswith("/IssueRemoteCommandResponse")

    error_schema = responses["409"]["content"]["application/json"]["schema"]

    assert error_schema["$ref"].endswith("/ErrorResponseContract")
