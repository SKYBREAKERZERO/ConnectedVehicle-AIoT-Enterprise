"""Guarded opt-in application patch: enable Redis TLS for real AWS Staging.

Run from the PROJECT ROOT after overlaying the Day37 files. Does not execute
unless --apply is explicitly supplied. Keeps non-TLS local development working.
"""
from __future__ import annotations

import argparse
from pathlib import Path

SETTINGS = Path("enterprise_platform/config/settings.py")
CLIENT = Path("enterprise_platform/cache/client.py")


def transform_settings(text: str) -> str:
    if "redis_tls_enabled: bool = False" in text:
        return text
    marker = '    redis_host: str = Field(default="localhost", min_length=1)'
    if text.count(marker) != 1:
        raise ValueError("BLOCKED: Settings Redis host anchor changed; manual review required")
    text = text.replace(marker, '    redis_tls_enabled: bool = False\n' + marker)
    validator = '    def validate_runtime_contracts(self) -> Settings:\n'
    if text.count(validator) != 1:
        raise ValueError("BLOCKED: Settings validator anchor changed; manual review required")
    addition = '''        if (self.app_env == AppEnvironment.STAGING and self.cloud_runtime == CloudRuntime.AWS
                and (not self.redis_tls_enabled or not self.redis_password)):
            raise ValueError("AWS Staging Redis requires TLS and injected Redis authentication")
'''
    return text.replace(validator, validator + addition)


def transform_client(text: str) -> str:
    if 'from redis.asyncio.connection import SSLConnection' in text:
        return text
    marker = 'from redis.asyncio import ConnectionPool, Redis\n'
    anchor = '    pool = ConnectionPool(\n'
    if text.count(marker) != 1 or text.count(anchor) != 1:
        raise ValueError("BLOCKED: redis.asyncio client connection anchors changed")
    text = text.replace(marker, marker + 'from redis.asyncio.connection import SSLConnection\n')
    return text.replace(anchor, '''    tls_options = (
        {"connection_class": SSLConnection, "ssl_cert_reqs": "required"}
        if settings.redis_tls_enabled else {}
    )
    pool = ConnectionPool(
        **tls_options,
''')


def main() -> None:
    p = argparse.ArgumentParser(description=__doc__)
    p.add_argument("--apply", action="store_true", help="Explicitly modify the two project files")
    a = p.parse_args()
    originals = [SETTINGS.read_text(encoding="utf-8"), CLIENT.read_text(encoding="utf-8")]
    modified = [transform_settings(originals[0]), transform_client(originals[1])]
    if not a.apply:
        print("DRY-RUN: Redis TLS patch anchors valid; rerun --apply after review")
        return
    if all(x == y for x, y in zip(originals, modified)):
        print("Redis TLS integration already present")
        return
    for path, value in zip((SETTINGS, CLIENT), modified):
        path.write_text(value, encoding="utf-8")
    print("Applied Redis TLS security integration to application Settings and client")


if __name__ == "__main__":
    main()
