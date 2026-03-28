# CSM Builder Image — Go 1.26 + pre-compiled YARA-X static library
# Rebuild only when upgrading YARA-X version.
#
# Build:
#   docker build -f build/Dockerfile.builder -t registry.internal.example/pidginhost/csm-builder:yara-1.14.0 .
#   docker push registry.internal.example/pidginhost/csm-builder:yara-1.14.0
#   docker tag registry.internal.example/pidginhost/csm-builder:yara-1.14.0 registry.internal.example/pidginhost/csm-builder:latest
#   docker push registry.internal.example/pidginhost/csm-builder:latest

FROM golang:1.26-alpine

# Build dependencies
RUN apk add --no-cache \
    gcc musl-dev pkgconf openssl-dev openssl-libs-static \
    git rust cargo make

# Install cargo-c (builds Rust libraries as C-compatible .a/.so)
RUN cargo install cargo-c@0.10.20 --locked

# Compile YARA-X v1.14.0 static library
RUN git clone --depth 1 --branch v1.14.0 https://github.com/VirusTotal/yara-x.git /tmp/yara-x \
    && cd /tmp/yara-x \
    && cargo cinstall -p yara-x-capi --release --prefix=/usr/local \
    && rm -rf /tmp/yara-x /root/.cargo/registry /root/.cargo/git

# Create stub libgcc_s.a — YARA-X references it but musl doesn't need it
RUN ar rcs /usr/local/lib/libgcc_s.a

# Verify YARA-X is available
RUN pkg-config --libs --static yara_x_capi

# Pre-warm Go module cache for faster builds
WORKDIR /workspace
