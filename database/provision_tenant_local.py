"""Cost-free tenant-bound role/Secret provisioning: LocalStack and loopback DB only."""

from __future__ import annotations

import argparse
import asyncio
import json
from collections.abc import Mapping
from contextlib import suppress
from secrets import token_urlsafe
from typing import Any, cast
from urllib.parse import urlparse

import boto3
from sqlalchemy import text

from database.bootstrap_cluster import SQLDriver, check_bootstrap
from database.credential_rotation import Target, password_manager, rotate
from database.schema_permissions import grant_runtimes, prepare_roles
from enterprise_platform.config.settings import Settings
from enterprise_platform.database.credentials import (
    DATABASE_USERS,
    DatabaseRuntime,
    bootstrap_database_settings,
    migration_database_settings,
    runtime_database_user,
)
from enterprise_platform.database.engine import create_database_engine
from enterprise_platform.database.management_identity import verify_migration_identity


def provision_local_cloud_identity(
    settings: Settings, secrets: Mapping[DatabaseRuntime, str], roles: Mapping[DatabaseRuntime, str]
) -> dict[str, object]:
    """LocalStack policy configuration evidence; IAM enforcement is not simulated reliably."""
    if not settings.aws_endpoint_url or urlparse(settings.aws_endpoint_url).hostname not in {
        "localhost",
        "127.0.0.1",
    }:
        raise ValueError("Cloud identity example requires loopback LocalStack")
    arguments: dict[str, Any] = dict(
        endpoint_url=settings.aws_endpoint_url,
        region_name=settings.aws_region,
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )
    kms = boto3.client("kms", **arguments)
    manager = boto3.client("secretsmanager", **arguments)
    iam: Any = boto3.client("iam", **arguments)
    alias = "alias/local-tenant-runtime-secrets"
    try:
        key = kms.describe_key(KeyId=alias)["KeyMetadata"]
    except kms.exceptions.NotFoundException:
        key = kms.create_key(Description="LocalStack tenant runtime example")["KeyMetadata"]
        kms.create_alias(AliasName=alias, TargetKeyId=key["KeyId"])
    kms.enable_key_rotation(KeyId=key["KeyId"])
    identities = {}
    for runtime, secret in secrets.items():
        manager.update_secret(SecretId=secret, KmsKeyId=key["Arn"])
        secret_arn = manager.describe_secret(SecretId=secret)["ARN"]
        name = "local-" + roles[runtime]
        trust = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Principal": {"Service": "ecs-tasks.amazonaws.com"},
                    "Action": "sts:AssumeRole",
                }
            ],
        }
        try:
            role = iam.create_role(RoleName=name, AssumeRolePolicyDocument=json.dumps(trust))[
                "Role"
            ]
        except iam.exceptions.EntityAlreadyExistsException:
            role = iam.get_role(RoleName=name)["Role"]
        policy = {
            "Version": "2012-10-17",
            "Statement": [
                {
                    "Effect": "Allow",
                    "Action": "secretsmanager:GetSecretValue",
                    "Resource": secret_arn,
                },
                {
                    "Effect": "Allow",
                    "Action": "kms:Decrypt",
                    "Resource": key["Arn"],
                    "Condition": {
                        "StringEquals": {
                            "kms:ViaService": f"secretsmanager.{settings.aws_region}.amazonaws.com",
                            "kms:EncryptionContext:SecretARN": secret_arn,
                        },
                    },
                },
            ],
        }
        iam.put_role_policy(
            RoleName=name, PolicyName="own-database-secret", PolicyDocument=json.dumps(policy)
        )
        identities[runtime] = {"role_arn": role["Arn"], "secret_arn": secret_arn}
    return {"identities": identities, "kms_key_arn": key["Arn"], "iam_enforcement_verified": False}


async def provision_tenant(settings: Settings, tenant: str) -> dict[str, object]:
    if settings.cloud_runtime.value != "localstack" or settings.app_env.value not in {
        "local",
        "test",
    }:
        raise ValueError("Tenant example is LocalStack-only")
    endpoint = settings.aws_endpoint_url
    if (
        not endpoint
        or urlparse(endpoint).hostname not in {"localhost", "127.0.0.1"}
        or settings.database_host not in {"localhost", "127.0.0.1"}
    ):
        raise ValueError("Tenant example requires loopback endpoints")
    roles = {runtime: runtime_database_user(runtime, tenant) for runtime in DATABASE_USERS}
    passwords = {runtime: token_urlsafe(32) for runtime in DATABASE_USERS}
    await prepare_roles(settings, roles)
    await grant_runtimes(settings, roles, tenant)
    client = boto3.client(
        "secretsmanager",
        endpoint_url=endpoint,
        region_name=settings.aws_region,
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )
    secrets = {
        runtime: (
            f"{settings.database_secret_prefix}/local/tenants/"
            f"{role.rsplit('__', 1)[1]}/database/{runtime}"
        )
        for runtime, role in roles.items()
    }
    for name in secrets.values():
        with suppress(client.exceptions.ResourceExistsException):
            await asyncio.to_thread(client.create_secret, Name=name)
    cloud = await asyncio.to_thread(provision_local_cloud_identity, settings, secrets, roles)
    targets = [Target(runtime, role, secrets[runtime], tenant) for runtime, role in roles.items()]
    async with password_manager(settings, targets) as backend:
        await rotate(
            settings,
            targets,
            {roles[runtime]: value for runtime, value in passwords.items()},
            client,
            backend,
        )
    return {
        "tenant_id": tenant,
        "roles": roles,
        "secrets": secrets,
        "scope": "localstack-only",
        **cloud,
    }


async def provision_monitor(settings: Settings) -> dict[str, object]:
    endpoint = settings.aws_endpoint_url
    if (
        settings.cloud_runtime.value != "localstack"
        or not endpoint
        or urlparse(endpoint).hostname not in {"localhost", "127.0.0.1"}
        or settings.database_host not in {"localhost", "127.0.0.1"}
    ):
        raise ValueError("Monitor example is loopback LocalStack-only")
    password = token_urlsafe(32)
    engine = create_database_engine(bootstrap_database_settings(settings))
    try:
        async with engine.begin() as connection:
            await check_bootstrap(connection, settings)
            driver = cast(SQLDriver, (await connection.get_raw_connection()).driver_connection)
            await driver.execute("""DO $$ BEGIN
                IF NOT EXISTS (SELECT FROM pg_roles WHERE rolname='observability_reader') THEN
                    CREATE ROLE observability_reader LOGIN;
                END IF;
            END $$;
            DO $$ DECLARE r record; BEGIN
                IF EXISTS (SELECT FROM pg_class c JOIN pg_roles u ON c.relowner=u.oid
                           WHERE u.rolname='observability_reader')
                OR EXISTS (SELECT FROM pg_proc p JOIN pg_roles u ON p.proowner=u.oid
                           WHERE u.rolname='observability_reader') THEN
                    RAISE EXCEPTION 'Monitor must not own database objects';
                END IF;
                FOR r IN SELECT parent.rolname AS parent FROM pg_auth_members m
                    JOIN pg_roles parent ON parent.oid=m.roleid
                    JOIN pg_roles child ON child.oid=m.member
                    WHERE child.rolname='observability_reader' LOOP
                    EXECUTE format('REVOKE %I FROM observability_reader',r.parent);
                END LOOP;
            END $$;
            ALTER ROLE observability_reader NOSUPERUSER NOBYPASSRLS
                NOCREATEDB NOCREATEROLE NOREPLICATION NOINHERIT;
            """)
    finally:
        await engine.dispose()
    migration = migration_database_settings(settings)
    engine = create_database_engine(migration)
    try:
        async with engine.begin() as connection:
            await connection.run_sync(
                lambda sync: verify_migration_identity(sync, migration.database_username)
            )
            driver = cast(SQLDriver, (await connection.get_raw_connection()).driver_connection)
            await driver.execute("""DO $$ DECLARE r record; BEGIN
                FOR r IN SELECT table_name,column_name FROM information_schema.columns
                    WHERE table_schema='public' LOOP
                    EXECUTE format('REVOKE ALL (%I) ON public.%I FROM observability_reader',
                                   r.column_name,r.table_name);
                END LOOP;
            END $$;
            REVOKE ALL ON ALL TABLES IN SCHEMA public FROM observability_reader;
            REVOKE ALL ON ALL SEQUENCES IN SCHEMA public FROM observability_reader;
            REVOKE ALL ON SCHEMA public FROM observability_reader;
            GRANT USAGE ON SCHEMA public TO observability_reader;
            GRANT EXECUTE ON FUNCTION public.runtime_health_summary() TO observability_reader;""")
            database = await connection.scalar(text("SELECT quote_ident(current_database())"))
            await driver.execute(
                f"REVOKE CREATE,TEMP ON DATABASE {database} FROM PUBLIC; "
                f"REVOKE ALL ON DATABASE {database} FROM observability_reader; "
                f"GRANT CONNECT ON DATABASE {database} TO observability_reader"
            )
    finally:
        await engine.dispose()
    client = boto3.client(
        "secretsmanager",
        endpoint_url=endpoint,
        region_name=settings.aws_region,
        aws_access_key_id="test",
        aws_secret_access_key="test",
    )
    name = f"{settings.database_secret_prefix}/local/database/observability"
    target = Target("observability", "observability_reader", name)
    async with password_manager(settings, [target]) as backend:
        await rotate(settings, [target], {target.role: password}, client, backend)
    return {"secret_id": name, "scope": "localstack-only"}


def main() -> None:
    parser = argparse.ArgumentParser()
    parser.add_argument("--tenant")
    parser.add_argument("--monitor", action="store_true")
    args = parser.parse_args()
    if args.monitor == bool(args.tenant):
        parser.error("Choose --tenant or --monitor")
    result = (
        provision_monitor(Settings()) if args.monitor else provision_tenant(Settings(), args.tenant)
    )
    print(json.dumps(asyncio.run(result), indent=2))


if __name__ == "__main__":
    main()
