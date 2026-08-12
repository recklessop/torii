# torii production image. Streamable-HTTP MCP gateway on :8400.
#
# Base image pinned by digest (#81): a tag is mutable, a digest is not, so a
# rebuild resolves the exact bytes that were reviewed rather than whatever
# `3.12-slim` points at that day. Refresh it deliberately with:
#   docker manifest inspect python:3.12-slim --verbose | grep digest
FROM python:3.12-slim@sha256:229a2c5bfa27522db7815ea81f9bed70af17ccb9de9fc7ad142b1877b5830d36

WORKDIR /app

# Install from the pinned, fully-hashed lockfile with --require-hashes: every
# artifact must match a recorded hash or the build fails, so a compromised or
# substituted upstream release cannot land silently. Regenerate the lock from
# the loose requirements.txt with:
#   uv pip compile requirements.txt --generate-hashes --python-version 3.12 -o requirements.lock
COPY requirements.lock /app/
RUN pip install --no-cache-dir --require-hashes -r requirements.lock

COPY torii /app/torii

ENV PYTHONUNBUFFERED=1 \
    TORII_HOST=0.0.0.0 \
    TORII_PORT=8400

# Run as an unprivileged user (#81). Nothing in torii needs root at runtime;
# a container escape from a non-root process has far less to work with. The
# app directory is owned by root and read-only to this user, which is all the
# process needs — it writes nothing to the image filesystem.
RUN useradd --system --no-create-home --uid 10001 torii
USER torii

EXPOSE 8400

LABEL org.opencontainers.image.source="https://github.com/recklessop/torii"

ENTRYPOINT ["python", "-m", "torii.server"]
