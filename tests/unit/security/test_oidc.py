from datetime import UTC, datetime, timedelta
from pathlib import Path
from uuid import uuid4

import jwt
import pytest
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from pydantic import ValidationError

from enterprise_platform.security.oidc import OIDCVerifier
from enterprise_platform.security.permissions import Permission
from tests.settings_helpers import isolated_settings


@pytest.fixture
def identity_keys(tmp_path: Path) -> tuple[OIDCVerifier, rsa.RSAPrivateKey]:
    private = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    public = tmp_path / "public.pem"
    public.write_bytes(
        private.public_key().public_bytes(
            serialization.Encoding.PEM, serialization.PublicFormat.SubjectPublicKeyInfo
        )
    )
    settings = isolated_settings(
        _env_file=None,
        app_env="test",
        oidc_issuer="https://identity.example",
        oidc_audience="vehicle-api",
        oidc_public_key_file=str(public),
    )
    return OIDCVerifier(settings), private


def claims() -> dict[str, object]:
    now = datetime.now(UTC)
    return {
        "iss": "https://identity.example",
        "aud": "vehicle-api",
        "sub": "operator",
        "iat": now,
        "exp": now + timedelta(minutes=5),
        "tenant_id": "tenant-a",
        "scope": "vehicle:command telemetry:read",
    }


def test_verified_identity_and_device_scope(
    identity_keys: tuple[OIDCVerifier, rsa.RSAPrivateKey],
) -> None:
    verifier, private = identity_keys
    token = jwt.encode(claims(), private, algorithm="RS256")
    context = verifier.verify(token)
    assert context.principal.tenant_id == "tenant-a"
    assert Permission.VEHICLE_COMMAND in context.granted_permissions
    vehicle = str(uuid4())
    payload = claims() | {
        "principal_type": "device",
        "vehicle_id": vehicle,
        "scope": "command:report telemetry:publish vehicle:command",
    }
    device = verifier.verify(jwt.encode(payload, private, algorithm="RS256"))
    assert device.principal.device_vehicle_id == vehicle
    assert device.granted_permissions == {Permission.COMMAND_REPORT, Permission.TELEMETRY_PUBLISH}


@pytest.mark.parametrize(
    "change",
    [
        {"iss": "https://attacker.example"},
        {"aud": "another-api"},
        {"exp": datetime.now(UTC) - timedelta(minutes=2)},
        {"token_use": "id"},
        {"tenant_id": ""},
        {"principal_type": "device", "vehicle_id": "invalid"},
    ],
)
def test_rejects_untrusted_claims(
    identity_keys: tuple[OIDCVerifier, rsa.RSAPrivateKey], change: dict[str, object]
) -> None:
    verifier, private = identity_keys
    with pytest.raises(jwt.InvalidTokenError):
        verifier.verify(jwt.encode(claims() | change, private, algorithm="RS256"))


def test_rejects_forged_signature_and_algorithm(
    identity_keys: tuple[OIDCVerifier, rsa.RSAPrivateKey],
) -> None:
    verifier, _ = identity_keys
    attacker = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    with pytest.raises(jwt.InvalidSignatureError):
        verifier.verify(jwt.encode(claims(), attacker, algorithm="RS256"))
    with pytest.raises(jwt.InvalidAlgorithmError):
        verifier.verify(jwt.encode(claims(), "attacker-secret" * 3, algorithm="HS256"))


def test_cognito_access_tokens_only(identity_keys: tuple[OIDCVerifier, rsa.RSAPrivateKey]) -> None:
    verifier, private = identity_keys
    verifier.settings.oidc_token_profile = "cognito"
    payload = claims() | {"client_id": "vehicle-api", "token_use": "access"}
    assert verifier.verify(jwt.encode(payload, private, algorithm="RS256"))
    for change in ({"client_id": "other"}, {"token_use": "id"}):
        with pytest.raises(jwt.InvalidTokenError):
            verifier.verify(jwt.encode(payload | change, private, algorithm="RS256"))


def test_production_rejects_local_service_token() -> None:
    with pytest.raises(ValidationError, match="OIDC"):
        isolated_settings(
            _env_file=None,
            app_env="production",
            api_service_token="x" * 64,
            api_service_tenant_id="tenant-a",
        )


def test_cognito_resource_server_scope_prefix(
    identity_keys: tuple[OIDCVerifier, rsa.RSAPrivateKey],
) -> None:
    verifier, private = identity_keys
    verifier.settings.oidc_scope_prefix = "vehicle-api/"
    payload = claims() | {"scope": "vehicle-api/vehicle:read vehicle:command"}
    context = verifier.verify(jwt.encode(payload, private, algorithm="RS256"))
    assert Permission.VEHICLE_READ in context.granted_permissions
    assert Permission.VEHICLE_COMMAND not in context.granted_permissions
