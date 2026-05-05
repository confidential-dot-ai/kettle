# Rust 1.94.0
FROM stagex/pallet-rust@sha256:2fbe7b164dd92edb9c1096152f6d27592d8a69b1b8eb2fc907b5fadea7d11668 AS build


# Import SOURCE_DATE_EPOCH, which should be set and then provided like this:
#   SOURCE_DATE_EPOCH="$(git log -1 --pretty=%ct)"
#   docker build . --build-arg "SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH"
# The SOURCE_DATE_EPOCH env var will be used to set build timestamps reproducibly.
ARG SOURCE_DATE_EPOCH
ENV SOURCE_DATE_EPOCH=$SOURCE_DATE_EPOCH

# Copy the Kettle source into the image.
WORKDIR /tmp/kettle
COPY . .

# Run a cargo build that explicitly targets musl, so the binary will be static.
RUN cargo build --release --locked --target x86_64-unknown-linux-musl

# Copy the binary into a stage named "artifact" so it can be extracted to the host:
#   docker build . --target=artifact --output "type=local,dest=$(pwd)/out/"
FROM scratch AS artifact
COPY --from=build /tmp/kettle/target/release/kettle /kettle

ENTRYPOINT ["/bin/sh"]
