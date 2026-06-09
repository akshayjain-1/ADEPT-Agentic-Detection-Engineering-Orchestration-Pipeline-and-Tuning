# ADEPT container image.
# Builds a single image containing both the MCP server and the agent; the
# docker-compose services select which entrypoint to run. Uses uv for fast,
# reproducible installs from the committed uv.lock.
FROM python:3.12-slim AS base

ENV PYTHONUNBUFFERED=1 \
    PYTHONDONTWRITEBYTECODE=1 \
    UV_COMPILE_BYTECODE=1 \
    UV_LINK_MODE=copy \
    VIRTUAL_ENV=/app/.venv \
    PATH="/app/.venv/bin:$PATH"

# Bring in the uv binary from the official distroless image.
COPY --from=ghcr.io/astral-sh/uv:0.11 /uv /uvx /bin/

# git is needed at runtime for the Sigma rules repository tools.
RUN apt-get update \
    && apt-get install -y --no-install-recommends git ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /app

# Install dependencies first (cached) using only the lock + manifest.
COPY pyproject.toml uv.lock README.md ./
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --no-install-project --extra mcp-server --extra agent

# Now copy the source and install the project itself.
COPY adept ./adept
RUN --mount=type=cache,target=/root/.cache/uv \
    uv sync --frozen --extra mcp-server --extra agent

# Drop privileges.
RUN useradd --create-home --uid 10001 adept \
    && mkdir -p /app/data \
    && chown -R adept:adept /app
USER adept

EXPOSE 8765

# Default to the MCP server; compose overrides for the agent service.
CMD ["adept-mcp"]
