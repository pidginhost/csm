# Building & Testing

## Build

```bash
# Standard build (no YARA-X)
go build ./cmd/csm/

# Build with YARA-X support (requires libyara_x_capi)
CGO_LDFLAGS="$(pkg-config --libs --static yara_x_capi)" go build -tags yara ./cmd/csm/
```

## Test

```bash
go test ./... -count=1           # all tests
go test -race -short ./...       # CI mode (race detector, skip slow tests)
```

## Lint

```bash
make lint                        # must pass before push
gofmt -l .                       # must produce no output
```

`make lint` uses repo-local cache directories under `.cache/` so the command behaves consistently in local shells, sandboxes, and CI runners.

Linter config in `.golangci.yml`: errcheck, govet, staticcheck, unused, ineffassign, gocritic, misspell, bodyclose, nilerr.

## CI/CD

GitLab CI (`.gitlab-ci.yml`) is the internal build pipeline. It runs lint/test/package jobs, publishes internal packages, mirrors to GitHub, and creates the public GitHub release artifacts.

| Stage | What it does |
|-------|-------------|
| **lint** | golangci-lint + gofmt check |
| **test** | `go test -v -race -short ./...` |
| **build-image** | Build CSM builder Docker image with YARA-X (manual trigger) |
| **build** | Two architectures (amd64 with YARA-X CGO, arm64 pure Go) |
| **package** | RPM + DEB via nFPM |
| **publish** | Internal GitLab Generic Package Registry (versioned + `latest`) |
| **cleanup** | Clean old package versions |
| **release** | GitLab release on tags matching `v*` |

## Public Releases

Public installs and upgrades use GitHub Releases:

1. Push changes and create a release tag.
2. Let CI build and publish the release artifacts.
3. Install or upgrade with `/opt/csm/deploy.sh install` or `/opt/csm/deploy.sh upgrade`.

The GitLab package registry and any GitLab-only deploy helpers are internal operational tooling, not part of the public GitHub workflow.

## Code Conventions

- **Imports:** stdlib, blank line, third-party, blank line, internal. Use `goimports -local github.com/pidginhost/csm`
- **Errors:** Return up the call stack. Wrap with `fmt.Errorf("context: %w", err)`
- **Store:** `store.Global()` singleton bbolt DB. Always nil-check.
- **State:** `state.Store` handles finding dedup, alert throttling, baseline tracking, latest findings persistence. Passed to subsystems at init
- **Web UI:** Vanilla JS, no framework, no build step. Tabler CSS framework. All API calls via `CSM.apiUrl()` / `CSM.post()`. Escape with `CSM.esc()`.

## Building the Documentation

```bash
cd docs
mdbook build              # generates docs/book/
mdbook serve              # local preview at http://localhost:3000
```
