# Rust 1.94.0
FROM docker.io/stagex/pallet-rust@sha256:2fbe7b164dd92edb9c1096152f6d27592d8a69b1b8eb2fc907b5fadea7d11668 AS build

# Copy in tpm2-tss so we can build attestation against it
COPY --from=docker.io/stagex/user-tpm2-tss . /

# Import SOURCE_DATE_EPOCH, which should be set and then provided like this:
#   SOURCE_DATE_EPOCH="$(git log -1 --pretty=%ct)"
#   docker build . --build-arg "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH"
# The SOURCE_DATE_EPOCH env var will be used to set build timestamps reproducibly.
ARG SOURCE_DATE_EPOCH
ENV SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH

# Copy the Kettle source into the image.
WORKDIR /tmp/kettle
COPY . .

# Tell pkg-config to always run in static mode, needed for libtss2
ENV PKG_CONFIG_ALL_STATIC=1

# Run a cargo build that explicitly targets musl, and links it statically.
ENV RUSTFLAGS='-C target-feature=+crt-static'
RUN cargo build \
  --bin kettle --features attest \
  --bin kettle-server --features server \
  --release --locked \
  --target x86_64-unknown-linux-musl

# Copy the binary into a stage named "artifact" so it can be extracted to the host:
#   docker build . --target=artifact --output "type=local,dest=$(pwd)/out/"
FROM scratch AS artifact
COPY --from=build /tmp/kettle/target/x86_64-unknown-linux-musl/release/kettle /kettle
