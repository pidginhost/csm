# CSM Builder Image — Go 1.26 + glibc + pre-compiled YARA-X static
# library for amd64. ARM64 is phase 2 of ROADMAP.md item 1.
#
# Base: AlmaLinux 8 (glibc 2.28). This is the oldest modern cPanel
# host we support — CloudLinux 8 / AlmaLinux 8 / RHEL 8 all ship
# glibc 2.28. A binary built here runs on every target distro we
# deploy to (glibc 2.28+ on EL8/EL9/Ubuntu 22.04/Ubuntu 24.04).
#
# Rationale for moving off Alpine+musl-static:
# The YARA-X 1.15.0 upgrade on 2026-04-16 put production into a
# deterministic SIGSEGV restart loop inside yrx_compiler_build. Root
# cause: fighting a musl-static + source-libunwind + Rust C-ABI
# combination that upstream YARA-X does not test. Moving to glibc-
# dynamic matches the toolchain upstream exercises and removes a
# whole class of link/runtime compatibility issues. See
# ROADMAP.md item 1 for the full decision record.
#
# Build:
#   docker build -f build/Dockerfile.builder -t csm/builder:glibc-2.28 .
#   docker tag csm/builder:glibc-2.28 csm/builder:latest

FROM almalinux:8

# System development tooling. PowerTools (aka CRB on newer Alma)
# exposes dev packages that are not in the base repos.
#
# libcurl-devel is mandatory: `cargo install cargo-c` pulls in
# curl-sys, which tries pkg-config for system libcurl and falls
# back to vendoring curl 8.18.0 if missing. The vendored curl
# requires OpenSSL >= 3.0.0 but AlmaLinux 8 ships OpenSSL 1.1.1, so
# the fallback fails to compile. Providing libcurl-devel (which
# installs libcurl.pc pointing at the system libcurl-1.1.1 build)
# makes curl-sys use the system library and skip the fallback.
#
# libxml2-devel / libssh2-devel are installed pre-emptively for the
# same reason: other transitive Rust deps reach for them via
# pkg-config before vendoring. Cheap insurance.
RUN dnf -y install dnf-plugins-core epel-release \
    && dnf config-manager --set-enabled powertools \
    && dnf -y install \
        gcc gcc-c++ make git curl tar xz which \
        pkgconf pkgconf-pkg-config \
        openssl openssl-devel \
        libcurl-devel libxml2-devel libssh2-devel \
        zlib-devel \
        perl autoconf automake libtool \
    && dnf clean all

# Go 1.26.2 from the official tarball. Alma 8's repos track older
# Go; we want the exact version csm is developed against.
ENV GO_VERSION=1.26.2
RUN curl -fsSL -o /tmp/go.tar.gz \
        https://go.dev/dl/go${GO_VERSION}.linux-amd64.tar.gz \
    && tar -xzf /tmp/go.tar.gz -C /usr/local \
    && rm /tmp/go.tar.gz
ENV PATH=/usr/local/go/bin:$PATH

# Rust toolchain via rustup. We install our own (not Alma's rust
# package) so we can pin a known-good version with rustup and
# programmatically add targets when arm64 cross-compilation lands.
ENV RUSTUP_HOME=/usr/local/rustup \
    CARGO_HOME=/usr/local/cargo \
    PATH=/usr/local/cargo/bin:/usr/local/go/bin:$PATH
RUN curl -fsSL https://sh.rustup.rs | \
        sh -s -- -y --default-toolchain stable --profile minimal

# cargo-c: builds Rust libraries as C-compatible .a + .h + .pc.
RUN cargo install cargo-c@0.10.20 --locked

# Compile YARA-X v1.14.0 static library, install to /usr/local. The
# --library-type=staticlib flag ensures cargo-c emits only the .a
# (not a .so) — we link YARA-X statically into the csm binary so
# there is no external YARA-X dependency at deploy time. The csm
# binary itself still links glibc dynamically (see the build job
# ldflags: -linkmode external without -extldflags '-static').
RUN git clone --depth 1 --branch v1.14.0 \
        https://github.com/VirusTotal/yara-x.git /tmp/yara-x \
    && cd /tmp/yara-x \
    && cargo cinstall -p yara-x-capi --release \
        --library-type=staticlib --prefix=/usr/local \
    && rm -rf /tmp/yara-x /root/.cargo/registry /root/.cargo/git

# Sanity-check: yara_x_capi.pc is reachable and links cleanly.
RUN pkg-config --libs --static yara_x_capi

WORKDIR /workspace
