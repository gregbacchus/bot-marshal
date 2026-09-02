FROM rust:1-slim AS build
WORKDIR /src
COPY . .
RUN cargo build --release --bin marshal

FROM debian:stable-slim
RUN apt-get update \
 && apt-get install -y --no-install-recommends ca-certificates \
 && rm -rf /var/lib/apt/lists/*
COPY --from=build /src/target/release/marshal /usr/local/bin/marshal
ENTRYPOINT ["marshal"]
