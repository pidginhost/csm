#!/usr/bin/env bash
# Run a Go command against this repository inside a Linux container.
#
# Most of CSM is //go:build linux -- fanotify, nftables, the spool watcher --
# so a macOS host cannot build or test it. Use this instead of hand-rolling a
# `container run` line with a fresh cache under /tmp. The caches below are
# stable across sessions and worktrees, and the host Go cache stays read-only.
#
#   scripts/go-linux.sh go test ./...
#   scripts/go-linux.sh go build ./cmd/...
#
# Environment:
#   GO_LINUX_IMAGE     override the image (default: exact go.mod Go version)
#   GO_LINUX_RUNTIME   override the runtime (default: ready Docker, else container)
#   GO_LINUX_MODCACHE  override the read-only host module cache seed; empty disables it
#   GO_LINUX_MEMORY    memory limit (default: 12g)
#   GO_LINUX_DRY_RUN=1 print the invocation instead of running it
set -euo pipefail

ROOT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
CALLER_DIR="$(pwd -P)"

if (($# == 0)); then
  printf 'usage: %s <command> [args...]\n' "${BASH_SOURCE[0]##*/}" >&2
  printf '  e.g. %s go test ./...\n' "${BASH_SOURCE[0]##*/}" >&2
  exit 2
fi

# The writable caches are stable across sessions and worktrees, but separate
# from the host Go caches and the checkout.
CACHE_BASE="${XDG_CACHE_HOME:-$HOME/.cache}"
if [[ "$CACHE_BASE" != /* ]]; then
  printf 'XDG_CACHE_HOME must be an absolute path: %s\n' "$CACHE_BASE" >&2
  exit 1
fi
if [[ -d "$CACHE_BASE" ]]; then
  CACHE_BASE="$(cd "$CACHE_BASE" && pwd -P)"
fi
CACHE_ROOT="${CACHE_BASE%/}/csm-linux"
BUILD_CACHE="$CACHE_ROOT/go-build"
MOD_CACHE="$CACHE_ROOT/go-mod"
LINT_CACHE="$CACHE_ROOT/golangci-lint"

# A container writing directly into the host module cache can create files the
# host user cannot replace, and Go's module-cache locks are not safe to
# coordinate across a macOS virtiofs boundary. Use the host download cache as a
# read-only local proxy and put container writes in the dedicated cache above.
HOST_MOD_CACHE=""
if [[ "${GO_LINUX_MODCACHE+x}" == x ]]; then
  HOST_MOD_CACHE="$GO_LINUX_MODCACHE"
  if [[ -n "$HOST_MOD_CACHE" && ! -d "$HOST_MOD_CACHE" ]]; then
    printf 'GO_LINUX_MODCACHE is not a directory: %s\n' "$HOST_MOD_CACHE" >&2
    exit 1
  fi
elif host_modcache="$(go env GOMODCACHE 2>/dev/null)" && [[ -d "$host_modcache" ]]; then
  HOST_MOD_CACHE="$host_modcache"
fi
if [[ -n "$HOST_MOD_CACHE" ]]; then
  HOST_MOD_CACHE="$(cd "$HOST_MOD_CACHE" && pwd -P)"
fi
if [[ -n "$HOST_MOD_CACHE" && "$HOST_MOD_CACHE" == "$MOD_CACHE" ]]; then
  printf 'host module cache must differ from the writable container cache: %s\n' "$MOD_CACHE" >&2
  exit 1
fi

# Use the full directive, including its patch component. A golang:1.N tag moves
# when a new patch is published and can silently differ from CI.
go_version="$(awk '$1 == "go" && NF == 2 {print $2; exit}' "$ROOT_DIR/go.mod")"
if [[ -z "$go_version" ]]; then
  printf 'could not read the go directive from %s/go.mod\n' "$ROOT_DIR" >&2
  exit 1
fi
IMAGE="${GO_LINUX_IMAGE:-golang:$go_version}"

# Prefer apple/container: it is the runtime this project is developed against on
# macOS, and picking a different one silently changes what a developer is
# actually testing.
#
# Caveat worth knowing: apple/container 1.2.2 keeps the rootfs snapshot of an
# auto-removed container -- roughly 2 GB per run, under
# ~/Library/Application Support/com.apple.container/snapshots, and not counted by
# `container system df`. Set GO_LINUX_RUNTIME=docker to avoid it on a host that
# runs Docker anyway, and prune the leftovers periodically.
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

# Preserve relative package and output paths when invoked below the repository
# root. Invocations from elsewhere intentionally start at /src.
CONTAINER_WORKDIR=/src
case "$CALLER_DIR" in
  "$ROOT_DIR") ;;
  "$ROOT_DIR"/*) CONTAINER_WORKDIR="/src${CALLER_DIR#"$ROOT_DIR"}" ;;
esac

mount_args=(
  -v "$ROOT_DIR:/src"
  -v "$BUILD_CACHE:/gocache"
  -v "$MOD_CACHE:/gomodcache"
  -v "$LINT_CACHE:/golangci-cache"
)
env_args=(
  -e GOCACHE=/gocache
  -e GOMODCACHE=/gomodcache
  -e GOLANGCI_LINT_CACHE=/golangci-cache
)

if [[ -n "$HOST_MOD_CACHE" ]]; then
  mount_args+=(-v "$HOST_MOD_CACHE:/gomodcache-host:ro")
  env_args+=(-e "GOPROXY=file:///gomodcache-host/cache/download,https://proxy.golang.org,direct")
fi

# A linked worktree's .git file points outside its root. Mount the common Git
# directory at that exact path so Go VCS stamping and Makefile git queries work.
# Optional locks keep read-only status queries from trying to refresh indexes.
if [[ -f "$ROOT_DIR/.git" ]]; then
  if ! git_common_dir="$(git -C "$ROOT_DIR" rev-parse --path-format=absolute --git-common-dir 2>/dev/null)" || [[ ! -d "$git_common_dir" ]]; then
    printf 'could not locate the common Git directory for %s\n' "$ROOT_DIR" >&2
    exit 1
  fi
  mount_args+=(-v "$git_common_dir:$git_common_dir:ro")
  env_args+=(-e GIT_OPTIONAL_LOCKS=0)
fi

# The Linux-only paths open fanotify and nftables handles. Without CAP_SYS_ADMIN
# those tests fail on permissions rather than behaviour, which looks like a
# broken suite instead of a missing capability.
cmd=(
  "$runtime" run --rm
  -m "${GO_LINUX_MEMORY:-12g}"
  --cap-add CAP_SYS_ADMIN
  "${mount_args[@]}"
  "${env_args[@]}"
  -w "$CONTAINER_WORKDIR"
  "$IMAGE" "$@"
)

if [[ "${GO_LINUX_DRY_RUN:-}" == 1 ]]; then
  printf '%q ' "${cmd[@]}"
  printf '\n'
  exit 0
fi

mkdir -p "$BUILD_CACHE" "$MOD_CACHE" "$LINT_CACHE"
exec "${cmd[@]}"
