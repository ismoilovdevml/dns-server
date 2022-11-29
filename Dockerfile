FROM rust AS builder

# kodni nusxalash
COPY Cargo.toml Cargo.lock /code/
COPY /src/ /code/src/

# kodni build qilish
WORKDIR /code
RUN cargo build --release

# runtime container
FROM debian:11 AS runtime

ENV RUST_LOG=info

# binary faylni nusxalash
COPY --from=builder /code/target/release/dnsserver /usr/local/bin/dnsserver

ENTRYPOINT ["/usr/local/bin/dnsserver"]