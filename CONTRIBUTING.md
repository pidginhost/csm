# Contributing to CSM

## Development Environment

**Requirements:**
- The Go version declared in `go.mod`
- `make`
- Pinned development tools installed with `make tools`
- YARA-X (optional, for YARA rule support - build with `-tags yara`)
- Linux host or VM (fanotify and nftables are Linux-only)

**Clone and build:**
```bash
git clone https://github.com/pidginhost/csm.git
cd csm
make build-linux        # cross-compile for Linux amd64
```

**Run tests:**
```bash
go test ./... -count=1 -race
```

**On a non-Linux host**, fanotify, nftables and the spool watcher are all behind
`//go:build linux`, so most of the daemon will not build locally. Run Go
commands inside a Linux container instead:

```bash
scripts/go-linux.sh go test ./... -count=1 -race
scripts/go-linux.sh go build ./...
```

The wrapper pins the image to the exact Go release in `go.mod`, grants
`CAP_SYS_ADMIN` (fanotify and nftables fail on permissions without it), and
keeps its writable caches in one shared location outside the repository
(`${XDG_CACHE_HOME:-$HOME/.cache}/csm-linux/`). The host module cache is mounted
read-only and used as a local download source; container writes go to the shared
cache instead. Repeated runs and separate worktrees therefore reuse cached work
without giving the container write access to the host Go cache or sharing its
locks.

The wrapper uses apple/container when it is installed and falls back to Docker.
Note that apple/container 1.2.2 keeps the rootfs snapshot of an auto-removed
container -- about 2 GB per run, under
`~/Library/Application Support/com.apple.container/snapshots`, and not reported
by `container system df`. Set `GO_LINUX_RUNTIME=docker` to avoid that on a host
that already runs Docker, and prune the leftover snapshots periodically.

Do not hand-roll a `container run` line with its own throwaway `GOCACHE` under
`/tmp` -- nothing reuses or cleans those up.

**Lint:**
```bash
make lint               # runs the pinned golangci-lint with repo-local caches
gofmt -l .              # check formatting
gofmt -w .              # fix formatting
```

## Code Style

- Format all Go code with `gofmt` before committing.
- All code must pass `golangci-lint` with no new warnings.
- Prefer explicit error handling over panics.
- Keep functions focused; avoid large multi-responsibility functions.
- New checks must include at least one unit test.

## Testing

```bash
go test ./... -count=1 -race                 # full suite with race detector
go test ./internal/checks/... -count=1 -race # specific package
```

Integration tests that require a live cPanel server are marked with `//go:build integration` and are not run by default.

## Commit Message Format

Use [Conventional Commits](https://www.conventionalcommits.org/):

```
<type>(<scope>): <short description>

[optional body]
```

Types: `feat`, `fix`, `docs`, `refactor`, `test`, `chore`

Examples:
```
feat(webui): add CSV export to history page
fix(daemon): prevent duplicate alerts on restart
docs: update configuration reference
```

## Pull Request Process

1. Fork the repo and create a branch from `main`.
2. Make your changes with tests.
3. Ensure `go test ./... -count=1 -race` and `make lint` both pass.
4. Open a PR with a clear description of what and why.
5. PRs require at least one review before merge.
6. Squash commits on merge if the branch history is noisy.

## Reporting Bugs

Open a GitHub issue with:
- CSM version (`csm version`)
- OS and kernel version
- Steps to reproduce
- Expected vs. actual behaviour
- Relevant log output (redact IPs/hostnames if needed)
