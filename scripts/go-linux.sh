#!/usr/bin/env bash
# Run a Go command against this repository inside a Linux container.
#
# Most of CSM is //go:build linux -- fanotify, nftables, the spool watcher --
# so a macOS host cannot build or test it at all. Use this instead of
# hand-rolling a `container run` line. Ad-hoc invocations each pointed GOCACHE
# at a fresh directory under /tmp (csm-review-gocache, csm-codex-gocache,
# csm-go-build-1267, ...); none were reused or removed, so /private/tmp reached
# 283 GB of Go caches while every run still compiled from scratch. The cache
# path below is derived rather than invented, so runs share it -- across
# sessions and across all worktrees under .claude/worktrees.
#
#   scripts/go-linux.sh go test ./...
#   scripts/go-linux.sh go build ./cmd/...
#
# Environment:
#   GO_LINUX_IMAGE     override the image (default: golang:<go.mod toolchain>)
#   GO_LINUX_RUNTIME   override the runtime (default: container, else docker)
#   GO_LINUX_MODCACHE  override the module cache (default: host $(go env GOMODCACHE))
#   GO_LINUX_MEMORY    memory limit (default: 12g)
#   GO_LINUX_DRY_RUN=1 print the invocation instead of running it
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"

if (($# == 0)); then
  printf 'usage: %s <command> [args...]\n' "${BASH_SOURCE[0]##*/}" >&2
  printf '  e.g. %s go test ./...\n' "${BASH_SOURCE[0]##*/}" >&2
  exit 2
fi

# Shared, stable cache root. Keyed by repo rather than by worktree so every
# worktree reuses one cache; kept outside the repo so it is never staged, and
# so it does not collide with the host-side $(CURDIR)/.cache the Makefile uses.
CACHE_ROOT="${XDG_CACHE_HOME:-$HOME/.cache}/csm-linux"
BUILD_CACHE="$CACHE_ROOT/go-build"
LINT_CACHE="$CACHE_ROOT/golangci-lint"

# The module cache holds extracted source only and is platform independent, so
# reuse the host's rather than downloading a second copy inside the container.
# A private module cache per repo duplicates ~1.3 GB for no benefit -- the same
# waste that filled /private/tmp, just relocated. Falls back to a derived path
# when there is no host toolchain (sandboxes, CI images without Go).
if [[ -n "${GO_LINUX_MODCACHE:-}" ]]; then
  MOD_CACHE="$GO_LINUX_MODCACHE"
elif host_modcache="$(go env GOMODCACHE 2>/dev/null)" && [[ -n "$host_modcache" ]]; then
  MOD_CACHE="$host_modcache"
else
  MOD_CACHE="$CACHE_ROOT/go-mod"
fi

# Pin the image to the toolchain go.mod declares, so a container run cannot
# quietly compile against a different Go than CI does.
go_minor="$(awk '/^go /{split($2, v, "."); print v[1]"."v[2]; exit}' "$ROOT_DIR/go.mod")"
if [[ -z "$go_minor" ]]; then
  printf 'could not read the go directive from %s/go.mod\n' "$ROOT_DIR" >&2
  exit 1
fi
IMAGE="${GO_LINUX_IMAGE:-golang:$go_minor}"

# Apple's container CLI is preferred on macOS; Docker is the fallback.
if [[ -n "${GO_LINUX_RUNTIME:-}" ]]; then
  runtime="$GO_LINUX_RUNTIME"
elif command -v container >/dev/null 2>&1; then
  runtime=container
elif command -v docker >/dev/null 2>&1; then
  runtime=docker
elif [[ "${GO_LINUX_DRY_RUN:-}" == 1 ]]; then
  runtime=container
else
  printf 'no container runtime found; install apple/container or docker\n' >&2
  exit 1
fi

# CAP_SYS_ADMIN: the linux-only paths open fanotify and nftables handles.
# Without it those tests fail on permissions rather than on behaviour, which
# reads as a broken suite instead of a missing capability.
cmd=(
  "$runtime" run --rm
  -m "${GO_LINUX_MEMORY:-12g}"
  --cap-add CAP_SYS_ADMIN
  -v "$ROOT_DIR:/src"
  -v "$BUILD_CACHE:/gocache"
  -v "$MOD_CACHE:/gomodcache"
  -v "$LINT_CACHE:/golangci-cache"
  -e GOCACHE=/gocache
  -e GOMODCACHE=/gomodcache
  -e GOLANGCI_LINT_CACHE=/golangci-cache
  -w /src
  "$IMAGE" "$@"
)

if [[ "${GO_LINUX_DRY_RUN:-}" == 1 ]]; then
  printf '%q ' "${cmd[@]}"
  printf '\n'
  exit 0
fi

mkdir -p "$BUILD_CACHE" "$MOD_CACHE" "$LINT_CACHE"
exec "${cmd[@]}"
