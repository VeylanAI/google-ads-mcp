FROM ghcr.io/astral-sh/uv:python3.11-bookworm-slim

ENV PYTHONDONTWRITEBYTECODE=1 \
    PYTHONUNBUFFERED=1 \
    PIP_DISABLE_PIP_VERSION_CHECK=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_TOOL_BIN_DIR=/usr/local/bin

    ARG APP_USER=appuser
    ARG APP_UID=1000
    ARG APP_GID=1000

    RUN groupadd --system --gid ${APP_GID} ${APP_USER} \
    && useradd --system --gid ${APP_GID} --uid ${APP_UID} --create-home ${APP_USER}

    RUN --mount=type=cache,target=/root/.cache/uv \
    --mount=type=bind,source=uv.lock,target=uv.lock \
    --mount=type=bind,source=pyproject.toml,target=pyproject.toml \
    uv sync --locked --no-install-project --no-dev

    COPY . /app
    RUN --mount=type=cache,target=/root.cache/uv \
    uv sync --locked --no-dev

ENV PATH="/app/.venv/bin:$PATH"

ENTRYPOINT [ ]

USER ${APP_USER}

CMD ["echo", "foo"]
