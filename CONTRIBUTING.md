# Contributing to CSM

This page covers the development setup, the code and commit rules, and how a pull request reaches the project.

## Development Environment

You need:

- The Go version declared in `go.mod`
- `make`
- The pinned development tools, installed with `make tools`
- YARA-X (optional, for YARA rule support; build with `-tags yara`)
- A Linux host or VM (fanotify and nftables are Linux-only)

### Clone and build

```bash
git clone https://github.com/pidginhost/csm.git
cd csm
make build-linux        # cross-compile for Linux amd64
```

### Run tests

```bash
go test ./... -count=1 -race
```

### On a non-Linux host

On a non-Linux host most of the daemon does not build, because fanotify, nftables and the spool watcher are all behind `//go:build linux`. Run Go commands inside a Linux container instead:

```bash
scripts/go-linux.sh go test ./... -count=1 -race
scripts/go-linux.sh go build ./...
```

The wrapper sets up the container like this:

- It pins the image to the exact Go release in `go.mod`.
- It grants the container `CAP_SYS_ADMIN`, because fanotify and nftables fail on permissions without it.
- It keeps its writable caches in one shared location outside the repository, `${XDG_CACHE_HOME:-$HOME/.cache}/csm-linux/`.

The host module cache is mounted read-only and used as a local download source. Container writes go to the shared cache instead. Repeated runs and separate worktrees therefore reuse cached work. The container gets no write access to the host Go cache and does not share its locks.

The wrapper uses apple/container when it is installed and falls back to Docker. apple/container 1.2.2 keeps the rootfs snapshot of an auto-removed container. Each run leaves about 2 GB under `~/Library/Application Support/com.apple.container/snapshots`, and `container system df` does not report it. Set `GO_LINUX_RUNTIME=docker` to avoid that on a host that already runs Docker, and prune the leftover snapshots periodically.

Do not hand-roll a `container run` line with its own throwaway `GOCACHE` under `/tmp`. Nothing reuses or cleans those up.

### Lint

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

## Web UI

- The scripts in `ui/static/js` are served as written, with no build step.
- The scripts may use syntax and browser APIs up to ES2019. A test rejects later syntax.
- Each script keeps its helpers inside a function scope and adds only to the `CSM` namespace.
- The shared runtime is `csm-core.js` (config and requests), `csm-format.js`, `csm-page.js` and `csm-live.js`, loaded in that order.
- The behavioral tests for the scripts need only Node: `node --test ui/`.

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

GitHub holds a mirror of the project's self-hosted GitLab repository, synced with a force push. That shapes what happens to a pull request:

- A pull request opened here is reviewed here, applied upstream, and arrives with the next sync.
- The mirror then closes the pull request on its own, so do not expect it to show as merged.

The mirror omits the internal deploy script and the GitLab pipeline gate tests. Everything left runs with `go test ./...` on a plain clone.

To send a change:

1. Fork the repo and create a branch from `main`.
2. Make your changes with tests.
3. Check that `go test ./... -count=1 -race` and `make lint` both pass.
4. Open a PR with a clear description of what and why.
5. PRs require at least one review before merge.
6. Squash commits on merge if the branch history is noisy.

## Reporting Bugs

Open a GitHub issue with:

- CSM version (`csm version`)
- OS and kernel version
- Steps to reproduce
- Expected vs. actual behavior
- Relevant log output (redact IPs/hostnames if needed)
