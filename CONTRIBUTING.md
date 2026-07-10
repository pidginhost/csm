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
