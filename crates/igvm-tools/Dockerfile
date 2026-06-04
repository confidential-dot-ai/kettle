FROM rust:1.86-bookworm AS builder
WORKDIR /src
COPY . .
RUN cargo build --release

FROM debian:bookworm-slim
COPY --from=builder /src/target/release/igvm-tools /usr/local/bin/
ENTRYPOINT ["igvm-tools"]
