# CSM Builder Image: Go 1.26 + pre-compiled YARA-X static library for
# both amd64 (host) and aarch64 (cross). Rebuild when upgrading YARA-X
# version or the cross-toolchain.
#
# Build:
#   docker build -f build/Dockerfile.builder -t csm/builder:yara-1.15.0 .
#   docker tag csm/builder:yara-1.15.0 csm/builder:latest
#
# What's inside:
#   /usr/local/{lib,include}                    YARA-X built for amd64-linux-musl
#   /usr/local/aarch64/{lib,include}            YARA-X built for aarch64-linux-musl
#   /opt/aarch64-linux-musl-cross/bin           aarch64 musl cross-toolchain
#   ~/.cargo/bin/rustup, cargo, rustc           full Rust toolchain with both targets
#
# build:linux-amd64 consumes /usr/local/*.
# build:linux-arm64 sets PKG_CONFIG_LIBDIR=/usr/local/aarch64/lib/pkgconfig
# and CC=aarch64-linux-musl-gcc, then Go's cgo links against /usr/local/aarch64/lib.

FROM golang:1.26-alpine

# Host build tooling. We install rustup below (not apk's rust) so we can
# add the aarch64-unknown-linux-musl target programmatically.
RUN apk add --no-cache \
        gcc musl-dev pkgconf openssl-dev openssl-libs-static \
        git make curl bash perl

# Rustup: canonical Rust manager, lets us add cross-targets.
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs \
        | sh -s -- -y --default-toolchain stable --profile minimal
ENV PATH="/root/.cargo/bin:${PATH}"

# aarch64 musl cross-toolchain. musl.cc is the standard source for
# pre-built musl cross-compilers. If availability becomes a concern,
# mirror the tarball to our own registry and swap the URL.
#
# Symlink every binary into /usr/local/bin. /usr/local/bin is on every
# sane default PATH, so the cross tools are reachable even if a CI
# runner replaces the image's ENV PATH (which the GitLab Kubernetes
# executor sometimes does). The symlinked wrappers follow back to
# /opt/.../bin and pick up the right sysroot via argv[0].
RUN curl -fsSL https://musl.cc/aarch64-linux-musl-cross.tgz | tar -xz -C /opt \
    && for bin in /opt/aarch64-linux-musl-cross/bin/*; do \
         ln -sf "$bin" "/usr/local/bin/$(basename "$bin")"; \
       done
ENV PATH="/opt/aarch64-linux-musl-cross/bin:${PATH}"

# Add the Rust target so cargo can cross-compile to aarch64-linux-musl.
RUN rustup target add aarch64-unknown-linux-musl

# Alpine's gcc is already a musl compiler (Alpine ships musl as libc), but
# upstream rustup's x86_64-unknown-linux-musl target -- and every build
# script it runs for the host triple -- looks for a binary literally
# called `musl-gcc` which Alpine doesn't provide. Shim it with a symlink
# to plain gcc. This is what Alpine's `musl-dev` would install if the
# wrapper existed on Alpine; we just wire it up ourselves.
RUN ln -s /usr/bin/gcc /usr/local/bin/musl-gcc \
    && ln -s /usr/bin/gcc /usr/local/bin/x86_64-linux-musl-gcc \
    && ln -s /usr/bin/ar  /usr/local/bin/musl-ar \
    && ln -s /usr/bin/ar  /usr/local/bin/x86_64-linux-musl-ar

# cargo-c: builds Rust libraries as C-compatible .a + .h + .pc.
RUN cargo install cargo-c@0.10.20 --locked

# Point openssl-sys at a vendored source build so the aarch64 cross
# compile doesn't try to link the amd64 openssl-libs-static installed
# above. OPENSSL_STATIC=1 forces static linkage; unset OPENSSL_DIR /
# _LIB_DIR so cargo picks the vendored path.
ENV OPENSSL_STATIC=1

# Fetch YARA-X source once, build twice (host then cross).
RUN git clone --depth 1 --branch v1.15.0 \
        https://github.com/VirusTotal/yara-x.git /tmp/yara-x

# Build for the native host arch (amd64) and install to /usr/local.
# --library-type=staticlib: the musl target drops cdylib support, so
# rustc never produces a .so and cargo-cinstall would fail at the
# final copy step. We only link the .a into the Go binary anyway
# (-linkmode external -extldflags '-static'), so shared output is
# unused noise.
RUN cd /tmp/yara-x \
    && cargo cinstall -p yara-x-capi --release \
        --library-type=staticlib --prefix=/usr/local

# Build for aarch64-linux-musl and install to /usr/local/aarch64. The
# CC_aarch64_... variable is what the cc crate looks up to find a cross
# compiler; CARGO_TARGET_..._LINKER is what cargo uses to link.
RUN cd /tmp/yara-x \
    && CC_aarch64_unknown_linux_musl=aarch64-linux-musl-gcc \
       CARGO_TARGET_AARCH64_UNKNOWN_LINUX_MUSL_LINKER=aarch64-linux-musl-gcc \
       AR_aarch64_unknown_linux_musl=aarch64-linux-musl-ar \
       cargo cinstall -p yara-x-capi --release \
           --library-type=staticlib \
           --target aarch64-unknown-linux-musl \
           --prefix=/usr/local/aarch64 \
    && rm -rf /tmp/yara-x /root/.cargo/registry /root/.cargo/git

# Stub libgcc_s.a for both prefixes. YARA-X references it but musl
# doesn't need it, so an empty archive satisfies the linker.
RUN ar rcs /usr/local/lib/libgcc_s.a \
    && aarch64-linux-musl-ar rcs /usr/local/aarch64/lib/libgcc_s.a

# Sanity-check both prefixes.
RUN pkg-config --libs --static yara_x_capi \
    && PKG_CONFIG_LIBDIR=/usr/local/aarch64/lib/pkgconfig \
       pkg-config --libs --static yara_x_capi

WORKDIR /workspace
