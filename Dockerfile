# Build stage
FROM rust:1.83-bookworm AS builder

WORKDIR /app

# Install build dependencies
RUN apt-get update && apt-get install -y \
    cmake \
    pkg-config \
    libssl-dev \
    && rm -rf /var/lib/apt/lists/*

# Copy manifests first for better caching
COPY Cargo.toml Cargo.lock ./
COPY crates/common/Cargo.toml crates/common/
COPY crates/parser/Cargo.toml crates/parser/
COPY crates/analyzer/Cargo.toml crates/analyzer/
COPY crates/indexer/Cargo.toml crates/indexer/
COPY crates/cli/Cargo.toml crates/cli/
COPY crates/daemon/Cargo.toml crates/daemon/
COPY crates/plugins/Cargo.toml crates/plugins/
COPY crates/lsp/Cargo.toml crates/lsp/
COPY crates/ai/Cargo.toml crates/ai/

# Create dummy source files for dependency caching
RUN mkdir -p crates/common/src && echo "pub fn dummy() {}" > crates/common/src/lib.rs
RUN mkdir -p crates/parser/src && echo "pub fn dummy() {}" > crates/parser/src/lib.rs
RUN mkdir -p crates/analyzer/src && echo "pub fn dummy() {}" > crates/analyzer/src/lib.rs
RUN mkdir -p crates/indexer/src && echo "pub fn dummy() {}" > crates/indexer/src/lib.rs
RUN mkdir -p crates/cli/src && echo "fn main() {}" > crates/cli/src/main.rs
RUN mkdir -p crates/daemon/src && echo "fn main() {}" > crates/daemon/src/main.rs
RUN mkdir -p crates/plugins/src && echo "pub fn dummy() {}" > crates/plugins/src/lib.rs
RUN mkdir -p crates/lsp/src && echo "fn main() {}" > crates/lsp/src/main.rs
RUN mkdir -p crates/ai/src && echo "pub fn dummy() {}" > crates/ai/src/lib.rs

# Build dependencies only
RUN cargo build --release -p rma-cli 2>/dev/null || true

# Copy actual source code
COPY crates/ crates/

# Touch source files to trigger rebuild
RUN find crates -name "*.rs" -exec touch {} \;

# Build the actual binary
RUN cargo build --release -p rma-cli

# Runtime stage
FROM debian:bookworm-slim

# Install runtime dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libssl3 \
    && rm -rf /var/lib/apt/lists/*

# Create non-root user
RUN useradd -m -u 1000 rma

# Copy binary from builder
COPY --from=builder /app/target/release/rma /usr/local/bin/rma

# Set ownership
RUN chown rma:rma /usr/local/bin/rma

# Switch to non-root user
USER rma
WORKDIR /workspace

# Default command
ENTRYPOINT ["rma"]
CMD ["--help"]

# Labels
LABEL org.opencontainers.image.title="RMA - Rust Monorepo Analyzer"
LABEL org.opencontainers.image.description="Ultra-fast code intelligence and security analysis"
LABEL org.opencontainers.image.source="https://github.com/bumahkib7/rust-monorepo-analyzer"
