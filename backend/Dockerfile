FROM rust:1.75-slim as builder

WORKDIR /app
COPY Cargo.toml .
RUN mkdir src && echo "fn main() {}" > src/main.rs
RUN cargo build --release
RUN rm -rf src

COPY src ./src
RUN touch src/main.rs && cargo build --release

FROM debian:bookworm-slim
RUN apt-get update && apt-get install -y ca-certificates && rm -rf /var/lib/apt/lists/*
COPY --from=builder /app/target/release/email-health-scanner /usr/local/bin/email-health-scanner
EXPOSE 8080
ENV PORT=8080
CMD ["email-health-scanner"]
