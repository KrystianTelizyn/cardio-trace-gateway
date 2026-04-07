FROM ghcr.io/astral-sh/uv:python3.13-trixie-slim
WORKDIR /app
ENV UV_NO_DEV=1
COPY pyproject.toml uv.lock ./
RUN uv sync --frozen --no-dev --no-install-project
COPY entrypoint.sh /entrypoint.sh
COPY src ./src
RUN chmod +x /entrypoint.sh && uv sync --frozen --no-dev
ENTRYPOINT ["/entrypoint.sh"]
