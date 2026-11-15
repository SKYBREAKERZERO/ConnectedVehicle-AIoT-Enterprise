"""Local Redis TLS and AUTH overlap evidence, without ElastiCache control-plane claims."""

from __future__ import annotations

import asyncio
from datetime import UTC, datetime, timedelta
from pathlib import Path
from subprocess import CalledProcessError
from uuid import uuid4

import pytest
from cryptography import x509
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.x509.oid import NameOID
from pydantic import SecretStr
from redis.exceptions import AuthenticationError, ConnectionError

from enterprise_platform.cache.client import create_redis_resources
from enterprise_platform.config.environment import AppEnvironment, CloudRuntime
from enterprise_platform.config.settings import Settings
from tests.e2e.test_independent_runtimes import docker


def certificates(path: Path) -> None:
    key = rsa.generate_private_key(public_exponent=65537, key_size=2048)
    subject = x509.Name([x509.NameAttribute(NameOID.COMMON_NAME, "localhost")])
    now = datetime.now(UTC)
    cert = (
        x509.CertificateBuilder()
        .subject_name(subject)
        .issuer_name(subject)
        .public_key(key.public_key())
        .serial_number(x509.random_serial_number())
        .not_valid_before(now - timedelta(minutes=2))
        .not_valid_after(now + timedelta(minutes=30))
        .add_extension(x509.SubjectAlternativeName([x509.DNSName("localhost")]), critical=False)
        .sign(key, hashes.SHA256())
    )
    (path / "redis.crt").write_bytes(cert.public_bytes(serialization.Encoding.PEM))
    (path / "redis.key").write_bytes(
        key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )


@pytest.mark.integration
async def test_redis_tls_overlap_and_replacement(
    tmp_path: Path, monkeypatch: pytest.MonkeyPatch
) -> None:
    certificates(tmp_path)
    monkeypatch.setenv("SSL_CERT_FILE", str(tmp_path / "redis.crt"))
    name = f"vehicle-day40-redis-{uuid4().hex[:10]}"
    old, new = uuid4().hex, uuid4().hex
    docker(
        "run",
        "-d",
        "--name",
        name,
        "--user",
        "0:0",
        "--entrypoint",
        "redis-server",
        "-p",
        "127.0.0.1::6379",
        "--mount",
        f"type=bind,source={tmp_path},target=/tls,readonly",
        "redis:7-alpine@sha256:858f009f9709ce576febc734aa78b8f6d624b82571f9ddb6bda4377c833b3499",
        "--port",
        "0",
        "--tls-port",
        "6379",
        "--tls-cert-file",
        "/tls/redis.crt",
        "--tls-key-file",
        "/tls/redis.key",
        "--tls-ca-cert-file",
        "/tls/redis.crt",
        "--tls-auth-clients",
        "no",
        "--requirepass",
        old,
    )
    try:
        try:
            port = int(docker("port", name, "6379").split(":")[-1])
        except CalledProcessError:
            pytest.fail(
                "Redis TLS container did not start: " + docker("logs", "--tail", "20", name)
            )

        async def ping(password: str, hostname: str = "localhost") -> bool:
            resources = create_redis_resources(
                Settings(
                    app_env=AppEnvironment.STAGING,
                    cloud_runtime=CloudRuntime.AWS,
                    redis_host=hostname,
                    redis_port=port,
                    redis_tls_enabled=True,
                    redis_password=SecretStr(password),
                )
            )
            try:
                return bool(await resources.client.ping())
            finally:
                await resources.client.aclose()
                await resources.pool.disconnect()

        for _ in range(30):
            try:
                if await ping(old):
                    break
            except ConnectionError:
                await asyncio.sleep(0.2)
        else:
            pytest.fail("Local Redis TLS did not become ready")

        with pytest.raises(ConnectionError):
            await ping(old, "127.0.0.1")

        def update(operator: str, rule: str) -> None:
            assert (
                docker(
                    "exec",
                    "-e",
                    f"REDISCLI_AUTH={operator}",
                    name,
                    "redis-cli",
                    "--tls",
                    "--cacert",
                    "/tls/redis.crt",
                    "ACL",
                    "SETUSER",
                    "default",
                    rule,
                )
                == "OK"
            )

        update(old, ">" + new)
        assert await ping(old)
        assert await ping(new)
        update(new, "<" + old)
        assert await ping(new)
        with pytest.raises(AuthenticationError):
            await ping(old)
    finally:
        docker("rm", "-f", name)
