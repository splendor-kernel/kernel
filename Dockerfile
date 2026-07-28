# syntax=docker/dockerfile:1.7@sha256:a57df69d0ea827fb7266491f2813635de6f17269be881f696fbfdf2d83dda33e

ARG RUST_VERSION=1.88
ARG RUST_TOOLCHAIN=1.88.0
ARG PYTHON_VERSION=3.11
ARG DEBIAN_SNAPSHOT=20260714T000000Z

FROM rust:${RUST_VERSION}-slim-bookworm@sha256:38bc5a86d998772d4aec2348656ed21438d20fcdce2795b56ca434cf21430d89 AS rust-builder

ARG RUST_TOOLCHAIN=1.88.0
ARG DEBIAN_SNAPSHOT

RUN printf '%s\n' \
        "deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT} bookworm main" \
        "deb [check-valid-until=no] https://snapshot.debian.org/archive/debian-security/${DEBIAN_SNAPSHOT} bookworm-security main" \
        > /etc/apt/sources.list \
    && rm -f /etc/apt/sources.list.d/debian.sources \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        build-essential=12.9 \
        ca-certificates=20230311+deb12u1 \
        pkg-config=1.8.1-1 \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /src
COPY . .

RUN RUSTUP_TOOLCHAIN="${RUST_TOOLCHAIN}" cargo build --locked --release -p splendorctl -p splendor-daemon

FROM rust-builder AS acceptance-builder

ARG RUST_TOOLCHAIN=1.88.0

RUN RUSTUP_TOOLCHAIN="${RUST_TOOLCHAIN}" cargo build --locked --release \
    -p splendor-kernel --example uc_e2e_s3_multi_agent_delegation \
    -p splendor-daemon --example resident_auth_key_tool \
    -p splendor-acceptance-action-host

FROM python:${PYTHON_VERSION}-slim-bookworm@sha256:b18992999dbe963a45a8a4da40ac2b1975be1a776d939d098c647482bcad5cba AS python-builder

WORKDIR /src
COPY python/ ./python/

RUN python -m venv /opt/splendor-venv \
    && /opt/splendor-venv/bin/python -m pip install --no-cache-dir --require-hashes -r ./python/build-requirements.txt \
    && /opt/splendor-venv/bin/python -m pip install --no-cache-dir --no-build-isolation ./python

FROM python:${PYTHON_VERSION}-slim-bookworm@sha256:b18992999dbe963a45a8a4da40ac2b1975be1a776d939d098c647482bcad5cba AS runtime

ARG SPLENDOR_IMAGE_VERSION=0.05-dev
ARG VCS_REF=unknown
ARG BUILD_DATE=unknown
ARG DEBIAN_SNAPSHOT

LABEL org.opencontainers.image.title="Splendor Kernel" \
      org.opencontainers.image.description="Splendor 0.05-dev governed runtime image for local, physical, and edge primitive validation" \
      org.opencontainers.image.version="${SPLENDOR_IMAGE_VERSION}" \
      org.opencontainers.image.revision="${VCS_REF}" \
      org.opencontainers.image.created="${BUILD_DATE}" \
      org.opencontainers.image.source="https://github.com/splendor-kernel/kernel" \
      org.opencontainers.image.licenses="Apache-2.0 OR MIT"

RUN printf '%s\n' \
        "deb [check-valid-until=no] https://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT} bookworm main" \
        "deb [check-valid-until=no] https://snapshot.debian.org/archive/debian-security/${DEBIAN_SNAPSHOT} bookworm-security main" \
        > /etc/apt/sources.list \
    && rm -f /etc/apt/sources.list.d/debian.sources \
    && apt-get update \
    && apt-get install -y --no-install-recommends \
        ca-certificates=20230311+deb12u1 \
        tini=0.19.0-1+b3 \
    && rm -rf /var/lib/apt/lists/* \
    && groupadd --system splendor \
    && useradd --system --gid splendor --home-dir /var/lib/splendor --create-home --shell /usr/sbin/nologin splendor \
    && mkdir -p /opt/splendor /workspace \
    && chown -R splendor:splendor /opt/splendor /workspace /var/lib/splendor

COPY --from=rust-builder /src/target/release/splendorctl /usr/local/bin/splendorctl
COPY --from=rust-builder /src/target/release/splendor-daemon /usr/local/bin/splendor-daemon
COPY --from=rust-builder /src/target/release/splendor-manager /usr/local/bin/splendor-manager
COPY --from=python-builder /opt/splendor-venv /opt/splendor-venv

WORKDIR /opt/splendor
COPY --chown=splendor:splendor examples/local-basic-loop ./examples/local-basic-loop
COPY --chown=splendor:splendor examples/daemon-client-local ./examples/daemon-client-local
COPY --chown=splendor:splendor examples/action-approval-flow ./examples/action-approval-flow
COPY --chown=splendor:splendor examples/circuit-breaker-basic ./examples/circuit-breaker-basic
COPY --chown=splendor:splendor examples/governance-audit-export ./examples/governance-audit-export
COPY --chown=splendor:splendor docs/releases ./docs/releases
COPY --chown=splendor:splendor docs/deployment/docker.md ./docs/deployment/docker.md
COPY --chown=splendor:splendor openapi/splendor-runtime-daemon.yaml ./openapi/splendor-runtime-daemon.yaml

ENV PATH="/opt/splendor-venv/bin:${PATH}" \
    PYTHONUNBUFFERED=1 \
    SPLENDOR_RUNTIME_MODE=local

USER splendor

ENTRYPOINT ["/usr/bin/tini", "--"]
CMD ["splendorctl", "--version"]

FROM runtime AS acceptance-runner

USER root

ARG DEBIAN_SNAPSHOT

RUN apt-get update \
    && apt-get install -y --no-install-recommends \
        nodejs=18.20.4+dfsg-1~deb12u2 \
        npm=9.2.0~ds1-1 \
        openssl=3.0.20-1~deb12u2 \
    && rm -rf /var/lib/apt/lists/*

COPY --from=acceptance-builder /src/target/release/examples/uc_e2e_s3_multi_agent_delegation /usr/local/bin/uc_e2e_s3_multi_agent_delegation
COPY --from=acceptance-builder /src/target/release/examples/resident_auth_key_tool /usr/local/bin/resident_auth_key_tool

WORKDIR /opt/splendor
COPY package.json package-lock.json ./
RUN npm ci --ignore-scripts \
    && ln -s /opt/splendor/node_modules/.bin/tsc /usr/local/bin/tsc

ENV PATH="/opt/splendor/node_modules/.bin:/opt/splendor-venv/bin:${PATH}"

USER splendor

FROM runtime AS acceptance-action-host

COPY --from=acceptance-builder /src/target/release/splendor-acceptance-action-host /usr/local/bin/splendor-acceptance-action-host

CMD ["splendor-acceptance-action-host"]

FROM python:${PYTHON_VERSION}-slim-bookworm@sha256:b18992999dbe963a45a8a4da40ac2b1975be1a776d939d098c647482bcad5cba AS acceptance-action-provider

RUN groupadd --system --gid 999 splendor \
    && useradd --system --uid 999 --gid splendor --home-dir /opt/splendor-provider --create-home --shell /usr/sbin/nologin splendor

WORKDIR /opt/splendor-provider
COPY --chown=splendor:splendor tests/e2e/use-cases/fixtures/action_provider.py ./
COPY --chown=splendor:splendor tests/e2e/use-cases/fixtures/acceptance_provider_protocol.py ./
COPY --chown=splendor:splendor tests/e2e/use-cases/fixtures/acceptance-operation-profiles.v3.json ./
COPY --chown=splendor:splendor tests/e2e/use-cases/fixtures/acceptance-operation-profiles.v3.sha256 ./
COPY --from=acceptance-builder /src/target/release/examples/resident_auth_key_tool /usr/local/bin/resident_auth_key_tool

ENV PYTHONUNBUFFERED=1
USER splendor
CMD ["python3", "action_provider.py"]

FROM runtime AS production
