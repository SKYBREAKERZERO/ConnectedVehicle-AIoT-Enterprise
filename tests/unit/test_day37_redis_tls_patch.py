from scripts.day37_apply_redis_tls import transform_settings, transform_client
import pytest

def test_setting_patch_has_tls_and_auth_fail_closed():
    text='''from x import y
    redis_host: str = Field(default="localhost", min_length=1)
    def validate_runtime_contracts(self) -> Settings:
        pass
'''
    out=transform_settings(text)
    assert 'redis_tls_enabled: bool = False' in out
    assert 'not self.redis_password' in out
    assert transform_settings(out)==out

def test_client_has_verified_cert_connection():
    text='''from redis.asyncio import ConnectionPool, Redis
    pool = ConnectionPool(
        host=settings.redis_host,
    )
'''
    out=transform_client(text)
    assert 'SSLConnection' in out and 'ssl_cert_reqs' in out and 'required' in out
    assert transform_client(out)==out

def test_unknown_client_rejected():
    with pytest.raises(ValueError,match='anchors changed'):
        transform_client('pool = redis.Redis()')
