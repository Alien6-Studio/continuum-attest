# Both stages are pinned by digest, not by tag. attest rejects tag
# references for capsules; its own image has to hold to the same rule.
#
# Build stage uses the same image as CI, so a container build and a CI
# build see the same toolchain.
FROM rust:1.93-bookworm@sha256:7c4ae649a84014c467d79319bbf17ce2632ae8b8be123ac2fb2ea5be46823f31 AS builder

WORKDIR /app
COPY . .

RUN cargo build --release --locked

FROM debian:bookworm-slim@sha256:88200866dfff7ea7f5cbcb6ec7c8a701889efe6fe859fe64d6990e4b07ea4171

LABEL org.opencontainers.image.title="Continuum Attest" \
      org.opencontainers.image.description="Verifiable CI/CD with cryptographic attestation" \
      org.opencontainers.image.source="https://github.com/Alien6-Studio/continuum-attest" \
      org.opencontainers.image.licenses="Apache-2.0"

# ca-certificates for the opt-in receipt delivery, git for the provenance
# the executor records from the workspace.
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates git \
    && rm -rf /var/lib/apt/lists/*

COPY --from=builder /app/target/release/attest /usr/local/bin/attest

RUN useradd -r -s /usr/sbin/nologin attest
USER attest
WORKDIR /workspace

ENTRYPOINT ["attest"]
