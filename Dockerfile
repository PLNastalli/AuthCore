FROM rust:1-bookworm AS builder
WORKDIR /build
COPY Cargo.toml ./
COPY src ./src
COPY migrations ./migrations
COPY openapi.json ./
RUN cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y --no-install-recommends ca-certificates && rm -rf /var/lib/apt/lists/*
RUN useradd --uid 10001 --create-home appuser
WORKDIR /app
COPY --from=builder /build/target/release/authcore /usr/local/bin/authcore
USER appuser
EXPOSE 3000
CMD ["authcore"]
