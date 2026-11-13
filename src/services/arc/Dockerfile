FROM rust:1.89.0-bookworm@sha256:948f9b08a66e7fe01b03a98ef1c7568292e07ec2e4fe90d88c07bb14563c84ff AS verification
WORKDIR /build/arc
COPY src/services/arc/Cargo.toml src/services/arc/Cargo.lock ./
COPY src/services/arc/vendor/arc/Cargo.toml src/services/arc/vendor/arc/Cargo.lock src/services/arc/vendor/arc/LICENSE src/services/arc/vendor/arc/README.md ./vendor/arc/
COPY src/services/arc/vendor/arc/src ./vendor/arc/src
COPY src/services/arc/vendor/arc/tests ./vendor/arc/tests
COPY src/services/arc/vendor/arc/benches ./vendor/arc/benches
RUN cargo fetch --locked
COPY src/services/arc/src ./src
COPY src/services/arc/tests ./tests
RUN cargo test --locked
# Validate the corrected fork against the unchanged upstream vectors as well.
RUN CARGO_TARGET_DIR=/build/vendor-target cargo test --locked --manifest-path vendor/arc/Cargo.toml --features suite_p256
# Run the upstream tests at the exact fetched revision with its own lockfile.
RUN set -- /usr/local/cargo/git/checkouts/arc-*/4f023d3/Cargo.toml; \
    test "$#" -eq 1; \
    test -f "$1"; \
    CARGO_TARGET_DIR=/build/upstream-target cargo test --locked --manifest-path "$1" \
      --features suite_p256 --test test_vectors --test test_protocol
RUN cargo build --locked --release --bin arc-feasibility

FROM debian:bookworm-slim@sha256:734a72b3d6142a71993b4bc580ca01d8ca687f77a2c422d96a961d3376b179bc
COPY --from=verification /build/arc/target/release/arc-feasibility /usr/local/bin/arc-feasibility
USER 10001:10001
CMD ["/usr/local/bin/arc-feasibility"]
