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
#
# No libunwind-static from apk here: Alpine's package is built with
# minidebuginfo enabled, which makes libunwind.a pull in liblzma symbols
# at link time. We build libunwind from source (for both archs, further
# down) with --disable-minidebuginfo to get a self-contained .a with
# zero external deps.
RUN apk add --no-cache \
        gcc g++ musl-dev pkgconf openssl-dev openssl-libs-static \
        git make curl bash perl autoconf automake libtool

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
#
# set -eu + pipefail: without pipefail, `curl -fsSL ... | tar -xz` will
# silently swallow a curl failure (tar happily reads 0 bytes and exits
# zero) and the layer "succeeds" with /opt empty. Download to a file
# first, verify size, then extract.
SHELL ["/bin/sh", "-ec"]
RUN set -eu; \
    echo "Fetching aarch64 cross-toolchain tarball"; \
    curl -fsSL -o /tmp/aarch64-cross.tgz https://musl.cc/aarch64-linux-musl-cross.tgz; \
    sz=$(stat -c %s /tmp/aarch64-cross.tgz); \
    echo "Downloaded $sz bytes"; \
    [ "$sz" -gt 50000000 ] || { echo "FATAL: tarball too small, aborting"; exit 1; }; \
    tar -xzf /tmp/aarch64-cross.tgz -C /opt; \
    rm -f /tmp/aarch64-cross.tgz; \
    test -x /opt/aarch64-linux-musl-cross/bin/aarch64-linux-musl-gcc; \
    for bin in /opt/aarch64-linux-musl-cross/bin/*; do \
        ln -sf "$bin" "/usr/local/bin/$(basename "$bin")"; \
    done; \
    ls /usr/local/bin/aarch64-linux-musl-gcc
ENV PATH="/opt/aarch64-linux-musl-cross/bin:${PATH}"

# Add the Rust target so cargo can cross-compile to aarch64-linux-musl.
RUN rustup target add aarch64-unknown-linux-musl

# Build a static libunwind for amd64 host. YARA-X 1.15.0 emits -lunwind
# in its generated .pc file, so we need a libunwind.a for the host link
# step too. Alpine's packaged libunwind-static would be simpler but it's
# compiled with minidebuginfo enabled, which makes libunwind.a reference
# lzma_* symbols (lzma_stream_footer_decode etc.) and forces every
# consumer to also link -llzma. Build from source with
# --disable-minidebuginfo to get a clean self-contained archive.
RUN set -eu; \
    curl -fsSL -o /tmp/libunwind.tar.gz \
        https://github.com/libunwind/libunwind/releases/download/v1.8.1/libunwind-1.8.1.tar.gz; \
    sz=$(stat -c %s /tmp/libunwind.tar.gz); \
    [ "$sz" -gt 500000 ] || { echo "FATAL: libunwind tarball too small ($sz bytes)"; exit 1; }; \
    tar -xzf /tmp/libunwind.tar.gz -C /tmp; \
    cd /tmp/libunwind-1.8.1; \
    ./configure --prefix=/usr/local \
        --disable-shared --enable-static \
        --disable-minidebuginfo --disable-documentation --disable-tests \
        CFLAGS="-O2 -fPIC" >/tmp/libunwind-amd64-configure.log 2>&1 \
        || { echo "configure failed:"; tail -40 /tmp/libunwind-amd64-configure.log; exit 1; }; \
    make -j"$(nproc)" >/tmp/libunwind-amd64-make.log 2>&1 \
        || { echo "make failed:"; tail -40 /tmp/libunwind-amd64-make.log; exit 1; }; \
    make install >/dev/null; \
    test -f /usr/local/lib/libunwind.a; \
    rm -rf /tmp/libunwind*; \
    echo "Built /usr/local/lib/libunwind.a"

# Cross-build a static libunwind for aarch64-linux-musl. Same reason as
# the amd64 build above; the musl.cc cross-toolchain doesn't ship
# libunwind, so source build against the cross-gcc is the only option.
RUN set -eu; \
    curl -fsSL -o /tmp/libunwind.tar.gz \
        https://github.com/libunwind/libunwind/releases/download/v1.8.1/libunwind-1.8.1.tar.gz; \
    sz=$(stat -c %s /tmp/libunwind.tar.gz); \
    [ "$sz" -gt 500000 ] || { echo "FATAL: libunwind tarball too small ($sz bytes)"; exit 1; }; \
    tar -xzf /tmp/libunwind.tar.gz -C /tmp; \
    cd /tmp/libunwind-1.8.1; \
    ./configure --host=aarch64-linux-musl --prefix=/usr/local/aarch64 \
        --disable-shared --enable-static \
        --disable-minidebuginfo --disable-documentation --disable-tests \
        CC=aarch64-linux-musl-gcc AR=aarch64-linux-musl-ar \
        RANLIB=aarch64-linux-musl-ranlib \
        CFLAGS="-O2 -fPIC" >/tmp/libunwind-configure.log 2>&1 \
        || { echo "configure failed:"; tail -40 /tmp/libunwind-configure.log; exit 1; }; \
    make -j"$(nproc)" >/tmp/libunwind-make.log 2>&1 \
        || { echo "make failed:"; tail -40 /tmp/libunwind-make.log; exit 1; }; \
    make install >/dev/null; \
    test -f /usr/local/aarch64/lib/libunwind.a; \
    rm -rf /tmp/libunwind*; \
    echo "Built /usr/local/aarch64/lib/libunwind.a"

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
