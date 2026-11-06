FROM python:3.12.16-slim-bookworm@sha256:da54eb86849fe19be7584d8b3f291fcf0c53c196760ab3d70dc6382f681ef9c0 AS build
WORKDIR /build
COPY infra/staging/requirements /locks
RUN python -m venv /opt/build && /opt/build/bin/pip install --no-cache-dir --require-hashes --only-binary=:all: -r /locks/build.lock
COPY pyproject.toml README.md ./
COPY apps ./apps
COPY connected_vehicle ./connected_vehicle
COPY enterprise_platform ./enterprise_platform
COPY simulators ./simulators
RUN /opt/build/bin/pip wheel --no-deps --no-build-isolation --no-index -w /dist . \
    && python -m venv --without-pip /opt/venv \
    && /opt/build/bin/pip --python /opt/venv install --no-cache-dir --require-hashes --only-binary=:all: -r /locks/runtime.lock \
    && /opt/build/bin/pip --python /opt/venv install --no-index --no-deps /dist/*.whl \
    && /opt/build/bin/pip --python /opt/venv check

FROM python:3.12.16-slim-bookworm@sha256:da54eb86849fe19be7584d8b3f291fcf0c53c196760ab3d70dc6382f681ef9c0
ARG REVISION
LABEL org.opencontainers.image.revision=$REVISION
ENV PATH="/opt/venv/bin:$PATH" PYTHONDONTWRITEBYTECODE=1 PYTHONUNBUFFERED=1
COPY --from=build /opt/venv /opt/venv
WORKDIR /app
USER 10001:10001
EXPOSE 8000
HEALTHCHECK --interval=5s --timeout=4s --start-period=30s --retries=3 CMD ["python", "-c", "import urllib.request; urllib.request.urlopen('http://127.0.0.1:8000/health/ready', timeout=3)"]
CMD ["python", "-m", "apps.api"]
