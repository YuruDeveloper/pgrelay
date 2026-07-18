FROM rust:1-alpine AS builder

# aws-lc-sys (rustls default crypto backend) needs a C toolchain, cmake and perl
RUN apk add --no-cache build-base cmake perl linux-headers

WORKDIR /build
COPY Cargo.toml Cargo.lock ./
COPY src ./src
RUN cargo build --release --locked
