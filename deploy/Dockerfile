FROM rust:1.83-alpine AS builder
RUN apk add --no-cache musl-dev
WORKDIR /build
COPY . .
RUN cargo build --release --target x86_64-unknown-linux-musl -p vsql-vault-server

FROM scratch
COPY --from=builder /build/target/x86_64-unknown-linux-musl/release/vsql-vault-server /vsql-vault
COPY --from=builder /build/migrations /migrations
EXPOSE 8420
ENTRYPOINT ["/vsql-vault"]
