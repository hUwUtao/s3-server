# Use the official Rust image as a parent image
FROM rust:bookworm as builder

# Set the working directory in the container
WORKDIR /usr/src/s3-server

# Copy the Cargo.toml and Cargo.lock files
COPY Cargo.toml Cargo.lock ./

# Copy the source code
COPY . .

# Build the application
RUN cargo build --release --bin s3-server

# Use a smaller base image for the final image
FROM ghcr.io/huwutao/flywheel:main

# Install dependencies
RUN apt-get update && apt-get install -y \
    ca-certificates \
    libc6 \
    && rm -rf /var/lib/apt/lists/*

# Set the working directory in the container
WORKDIR /app

# Copy the built executable from the builder stage
COPY --from=builder /usr/src/s3-server/target/release/s3-server /usr/bin

# Expose the port the app runs on
EXPOSE 8014

# Run the binary
CMD ["/usr/bin/s3-server", "--fs-root", "/storage"]
