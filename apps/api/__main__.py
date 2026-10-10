from __future__ import annotations

import uvicorn

from enterprise_platform.config.settings import get_settings


def main() -> None:
    settings = get_settings()
    uvicorn.run(
        "apps.api.main:app",
        host=settings.app_host,
        port=settings.app_port,
        timeout_graceful_shutdown=int(settings.worker_shutdown_timeout_seconds),
    )


if __name__ == "__main__":
    main()
