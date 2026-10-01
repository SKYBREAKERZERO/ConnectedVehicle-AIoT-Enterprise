from enterprise_platform.config.environment import AppEnvironment, CloudRuntime
from enterprise_platform.config.settings import Settings


def test_default_settings_use_local_environment() -> None:
    settings = Settings(_env_file=None)

    assert settings.app_env is AppEnvironment.LOCAL
    assert settings.cloud_runtime is CloudRuntime.LOCALSTACK
    assert settings.aws_region == "ap-northeast-1"


def test_application_port_accepts_valid_value() -> None:
    settings = Settings(app_port=9000, _env_file=None)

    assert settings.app_port == 9000


def test_default_aws_sdk_resilience_settings() -> None:
    settings = Settings(_env_file=None)

    assert settings.aws_connect_timeout_seconds == 3.0
    assert settings.aws_read_timeout_seconds == 10.0
    assert settings.aws_max_attempts == 3


def test_default_database_settings() -> None:
    settings = Settings(_env_file=None)

    assert settings.database_host == "localhost"
    assert settings.database_port == 5432
    assert settings.database_name == "connected_vehicle"
    assert settings.database_username == "connected_vehicle"
    assert settings.database_password.get_secret_value() == "connected_vehicle"

    assert settings.database_pool_size == 10
    assert settings.database_max_overflow == 20
    assert settings.database_pool_timeout_seconds == 30.0
    assert settings.database_connect_timeout_seconds == 5.0
    assert settings.database_health_timeout_seconds == 3.0


def test_default_redis_settings() -> None:
    settings = Settings()

    assert settings.redis_host == "localhost"
    assert settings.redis_port == 16379
    assert settings.redis_db == 0
    assert settings.redis_connect_timeout_seconds == 3.0
    assert settings.redis_socket_timeout_seconds == 5.0
    assert settings.redis_health_timeout_seconds == 5.0
    assert settings.redis_max_connections == 50
    assert settings.redis_key_prefix == "connected-vehicle"
