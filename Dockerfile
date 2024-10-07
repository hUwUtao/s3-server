# Use the official Rust image as a parent image
FROM rust:slim as builder

# Set the working directory in the container
WORKDIR /usr/src/s3-server

# Copy the Cargo.toml and Cargo.lock files
COPY Cargo.toml Cargo.lock ./

# Copy the source code
COPY src ./src

# Build the application
RUN cargo build --release --bin s3-server

# Use a smaller base image for the final image
FROM debian:buster-slim

# Set the working directory in the container
WORKDIR /usr/local/bin

# Copy the built executable from the builder stage
COPY --from=builder /usr/src/s3-server/target/release/s3-server .

# Expose the port the app runs on
EXPOSE 8014

# Run the binary
CMD ["./s3-server"]
